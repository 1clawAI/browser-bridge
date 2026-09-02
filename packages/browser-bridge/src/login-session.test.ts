// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WebSocket } from "ws";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { startBridge, type BridgeHandle } from "./bridge.js";
import { LocalVaultDriver } from "./drivers/local.js";
import { sealVault, type VaultEntry } from "./drivers/local-vault-file.js";

/**
 * A fill must actually log in.
 *
 * Reported from outside: the ceremony typed a credential into a throwaway tab
 * and closed it without submitting, so nothing ever logged in and no session
 * reached the agent. Three separate defects sat behind that, and every unit
 * test passed through all of them because `FakeCdpTransport` answers `{ok:true}`
 * to any command — including `DOM.querySelector` without a nodeId, which
 * focuses nothing, and `Input.dispatchKeyEvent`, which was never sent.
 *
 * This test is the one that could not have passed: a real browser, a real login
 * form that sets a real cookie, and an assertion that the *agent's own tab* is
 * authenticated afterwards. That last part is the point of the design — the
 * credential goes into a page the agent has never scripted, and only the
 * session comes back.
 */
const CHROME =
  process.env.ONECLAW_BRIDGE_CHROME ??
  {
    darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    linux: "/usr/bin/google-chrome",
  }[process.platform as "darwin" | "linux"] ??
  "";
const HAVE_CHROME = CHROME !== "" && existsSync(CHROME);
const PASSPHRASE = "a-long-enough-passphrase";
const PASSWORD = "hunter2-session-test!";
const LAUNCH_ARGS = [
  "--headless=new",
  ...(process.env.CI && process.platform === "linux"
    ? ["--no-sandbox", "--disable-dev-shm-usage"]
    : []),
];

let server: Server;
let origin = "";
let profileUpdates: string[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const cookies = req.headers.cookie ?? "";
    const signedIn = cookies.includes("session=ada");

    if (url.pathname === "/login") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(`<!doctype html><body><form action="/session" method="post">
        <input id="username" name="username" value="ada@example.com">
        <input id="password" name="password" type="password">
      </form></body>`);
      return;
    }
    if (url.pathname === "/session" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const pw = new URLSearchParams(body).get("password") ?? "";
        if (pw !== PASSWORD) {
          res.writeHead(302, { location: "/login?bad=1" }).end();
          return;
        }
        // A real session cookie, scoped to the browser context that gets it.
        res.writeHead(302, { location: "/account", "set-cookie": "session=ada; Path=/" }).end();
      });
      return;
    }
    if (url.pathname === "/account") {
      res.writeHead(signedIn ? 200 : 401, { "content-type": "text/html" });
      res.end(
        signedIn
          ? '<!doctype html><body><div id="who">ada@example.com</div></body>'
          : '<!doctype html><body><div id="who">anonymous</div></body>',
      );
      return;
    }
    if (url.pathname === "/profile" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        if (!signedIn) {
          res.writeHead(401).end("not signed in");
          return;
        }
        profileUpdates.push(new URLSearchParams(body).get("display_name") ?? "");
        res.writeHead(200).end("ok");
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

/** A minimal CDP client, standing in for the agent's framework. */
class Agent {
  #ws: WebSocket;
  #next = 1;
  readonly #pending = new Map<number, (m: Record<string, unknown>) => void>();

  private constructor(ws: WebSocket) {
    this.#ws = ws;
    this.#ws.on("message", (data) => {
      const msg = JSON.parse(String(data)) as { id?: number };
      if (typeof msg.id === "number") {
        this.#pending.get(msg.id)?.(msg as Record<string, unknown>);
        this.#pending.delete(msg.id);
      }
    });
  }

  static async connect(url: string): Promise<Agent> {
    const ws = new WebSocket(url);
    await new Promise((res, rej) => {
      ws.once("open", res);
      ws.once("error", rej);
    });
    return new Agent(ws);
  }

  send(msg: Record<string, unknown>): Promise<Record<string, unknown>> {
    const id = this.#next++;
    return new Promise((resolve) => {
      this.#pending.set(id, resolve);
      this.#ws.send(JSON.stringify({ id, ...msg }));
    });
  }

  close(): void {
    this.#ws.close();
  }
}

let bridge: BridgeHandle | undefined;
afterEach(async () => {
  await bridge?.close();
  bridge = undefined;
});

async function start() {
  const entry: VaultEntry = {
    id: "acme",
    secret: PASSWORD,
    loginUrl: `${origin}/login`,
    allowedHosts: ["127.0.0.1"],
  };
  const dir = mkdtempSync(join(tmpdir(), "1claw-session-"));
  const path = join(dir, "vault.json");
  writeFileSync(path, JSON.stringify(await sealVault([entry], PASSPHRASE)));
  const backend = new LocalVaultDriver({ path, passphrase: PASSPHRASE });
  await backend.open();
  bridge = await startBridge({
    executablePath: CHROME,
    backend,
    host: "127.0.0.1",
    port: 0,
    args: LAUNCH_ARGS,
  });
  return bridge!;
}

describe.skipIf(!HAVE_CHROME)("a fill logs in, and the agent gets the session", () => {
  it("submits the form and leaves the agent's own tab authenticated", async () => {
    profileUpdates = [];
    const b = await start();

    // Connected the way an agent framework connects: over the proxy, through
    // the gate. Nothing here bypasses what a real caller is subject to.
    const agent = await Agent.connect(b.url);

    // The agent cannot create a browser context — Target.createBrowserContext
    // is refused, or re-attaching outside the gate would make the gate moot.
    // The proxy assigns it one and places its targets there.
    const refused = await agent.send({ method: "Target.createBrowserContext" });
    expect(refused.error, "an agent must not be able to make its own context").toBeTruthy();

    const made = await agent.send({
      method: "Target.createTarget",
      params: { url: `${origin}/account` },
    });
    const agentTarget = (made as { result?: { targetId?: string } }).result?.targetId!;
    const attached = await agent.send({
      method: "Target.attachToTarget",
      params: { targetId: agentTarget, flatten: true },
    });
    const agentSession = (attached as { result?: { sessionId?: string } }).result?.sessionId!;

    const read = async () => {
      const out = await agent.send({
        sessionId: agentSession,
        method: "Runtime.evaluate",
        params: {
          expression: "document.querySelector('#who')?.textContent ?? ''",
          returnByValue: true,
        },
      });
      return (out as { result?: { result?: { value?: string } } }).result?.result?.value ?? "";
    };

    /** Poll until the page renders; navigation resolves before the DOM exists. */
    const readWhen = async (want: string) => {
      let v = "";
      for (let i = 0; i < 60 && v !== want; i++) {
        v = await read();
        if (v !== want) await new Promise((r) => setTimeout(r, 150));
      }
      return v;
    };

    // Before: nobody.
    expect(await readWhen("anonymous")).toBe("anonymous");

    const result = await b.callTool(
      "request_fill",
      { binding_id: "acme", target_id: agentTarget, selector: "#password" },
      () => ({
        tabOrigin: origin,
        frameOrigin: origin,
        formActionOrigin: origin,
        frameId: agentTarget,
        generation: 0,
        formPath: "/login",
        fieldNames: ["username", "password"],
        redirectChain: [],
        currentGeneration: 0,
      }),
    );
    expect(result).toMatchObject({ status: "filled" });
    expect(JSON.stringify(result)).not.toContain(PASSWORD);

    // After: the agent's own tab is signed in, because the fill's throwaway
    // page was created in the agent's context and the cookie belongs to the
    // context rather than the page.
    await agent.send({ sessionId: agentSession, method: "Page.reload" });
    expect(
      await readWhen("ada@example.com"),
      "the agent's tab never became authenticated",
    ).toBe("ada@example.com");

    // And it can now act as that user — the thing a login is for.
    const posted = await agent.send({
      sessionId: agentSession,
      method: "Runtime.evaluate",
      params: {
        expression: `fetch('/profile', { method: 'POST', credentials: 'include',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: 'display_name=Ada+L' }).then(r => r.status)`,
        awaitPromise: true,
        returnByValue: true,
      },
    });
    expect((posted as { result?: { result?: { value?: number } } }).result?.result?.value).toBe(200);
    expect(profileUpdates).toEqual(["Ada L"]);
    agent.close();
  }, 120_000);
});

describe.skipIf(HAVE_CHROME)("a fill logs in, and the agent gets the session", () => {
  it("is skipped because no Chromium was found", () => {
    expect(HAVE_CHROME).toBe(false);
  });
});
