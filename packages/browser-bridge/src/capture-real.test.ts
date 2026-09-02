// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * The whole no-see chain, against a real browser.
 *
 * A fill types a stored secret into a page; a capture reads a site-generated
 * secret out of one. This drives both, end to end: the bridge registers an
 * account, logs in with it, and then — while the agent's tab is authenticated —
 * opens a page the agent has never scripted, generates an API key, reads it, and
 * stores it in the vault. The agent's tool results carry a status and an id, and
 * the key appears in neither. The site records the key it issued, and the test
 * requires the vault to hold exactly that value.
 */
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WebSocket } from "ws";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { startBridge, type BridgeHandle } from "./bridge.js";
import { LocalVaultDriver } from "./drivers/local.js";
import { openVault, sealVault } from "./drivers/local-vault-file.js";

const CHROME =
  process.env.ONECLAW_BRIDGE_CHROME ??
  {
    darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    linux: "/usr/bin/google-chrome",
  }[process.platform as "darwin" | "linux"] ??
  "";
const HAVE_CHROME = CHROME !== "" && existsSync(CHROME);
const PASSPHRASE = "a-long-enough-passphrase";
const LAUNCH_ARGS = [
  "--headless=new",
  ...(process.env.CI && process.platform === "linux" ? ["--no-sandbox", "--disable-dev-shm-usage"] : []),
];

let server: Server;
let origin = "";
let issuedKey = ""; // the key the site actually handed out

function randomKey(): string {
  // Deterministic-free but unique enough for one test run.
  return "sk_live_" + Buffer.from(String(process.hrtime.bigint())).toString("hex");
}

beforeAll(async () => {
  const users = new Map<string, string>();
  const body = (req: import("node:http").IncomingMessage) =>
    new Promise<string>((r) => {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => r(b));
    });

  server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const signedIn = (req.headers.cookie ?? "").includes("session=ada");

    if (url.pathname === "/signup" && req.method === "GET") {
      res.end(`<!doctype html><body><form action="/signup" method="post">
        <input id="email" name="email"><input id="password" name="password" type="password">
        <button id="go" type="submit">Sign up</button></form></body>`);
      return;
    }
    if (url.pathname === "/signup" && req.method === "POST") {
      const p = new URLSearchParams(await body(req));
      users.set(p.get("email") ?? "", p.get("password") ?? "");
      res.writeHead(302, { location: "/welcome" }).end();
      return;
    }
    if (url.pathname === "/welcome") return void res.end("<!doctype html><h1 id=ok>Welcome</h1>");
    if (url.pathname === "/login" && req.method === "GET") {
      res.end(`<!doctype html><body><form action="/session" method="post">
        <input id="username" name="username" value="ada@example.com">
        <input id="password" name="password" type="password"></form></body>`);
      return;
    }
    if (url.pathname === "/session" && req.method === "POST") {
      const p = new URLSearchParams(await body(req));
      if (users.get(p.get("username") ?? "") !== p.get("password")) {
        res.writeHead(302, { location: "/login?bad=1" }).end();
        return;
      }
      res.writeHead(302, { location: "/account", "set-cookie": "session=ada; Path=/" }).end();
      return;
    }
    if (url.pathname === "/account") {
      res
        .writeHead(signedIn ? 200 : 401, { "content-type": "text/html" })
        .end(`<!doctype html><body><div id="who">${signedIn ? "ada@example.com" : "anonymous"}</div></body>`);
      return;
    }
    // The API-keys page: a Generate button that asks the server for a key and
    // drops it into a field. Only for a logged-in session.
    if (url.pathname === "/settings/api") {
      if (!signedIn) return void res.writeHead(401).end("not signed in");
      res.writeHead(200, { "content-type": "text/html" }).end(`<!doctype html><body>
        <input id="api-key" value="">
        <button id="generate">Generate</button>
        <script>document.getElementById('generate').addEventListener('click', async () => {
          const r = await fetch('/issue-key', { method: 'POST', credentials: 'include' });
          const { key } = await r.json();
          document.getElementById('api-key').value = key;
        });</script></body>`);
      return;
    }
    if (url.pathname === "/issue-key" && req.method === "POST") {
      if (!signedIn) return void res.writeHead(401).end("not signed in");
      issuedKey = randomKey();
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ key: issuedKey }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

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

async function start(vaultPath: string) {
  const backend = new LocalVaultDriver({ path: vaultPath, passphrase: PASSPHRASE });
  await backend.open();
  bridge = await startBridge({ executablePath: CHROME, backend, host: "127.0.0.1", port: 0, args: LAUNCH_ARGS });
  return bridge!;
}

describe.skipIf(!HAVE_CHROME)("register, log in, and capture a generated key", () => {
  it("stores the site's API key in the vault, and the agent never sees it", async () => {
    issuedKey = "";
    const dir = mkdtempSync(join(tmpdir(), "1claw-capture-real-"));
    const vaultPath = join(dir, "vault.json");
    writeFileSync(
      vaultPath,
      JSON.stringify(
        await sealVault(
          {
            entries: [],
            registrations: [
              {
                id: "acme",
                signupUrl: `${origin}/signup`,
                loginUrl: `${origin}/login`,
                username: "ada@example.com",
                allowedHosts: ["127.0.0.1"],
                usernameSelector: "#email",
                passwordSelector: "#password",
                submitSelector: "#go",
                success: { urlChanges: true },
              },
            ],
            captures: [
              {
                id: "acme-key",
                captureUrl: `${origin}/settings/api`,
                loginUrl: `${origin}/login`,
                allowedHosts: ["127.0.0.1"],
                generateSelector: "#generate",
                valueSelector: "#api-key",
                valueProp: "value",
              },
            ],
          },
          PASSPHRASE,
        ),
      ),
    );

    const b = await start(vaultPath);
    const observe = (frameId: string) => () => ({
      tabOrigin: origin,
      frameOrigin: origin,
      formActionOrigin: origin,
      frameId,
      generation: 0,
    });

    // 1. Register — creates the account, stores the generated password.
    const reg = await b.callTool("begin_credential_registration", { site_id: "acme" }, observe("acme"));
    expect(reg).toMatchObject({ status: "registered", bindingId: "acme" });

    // 2. The agent opens its own tab and logs in via a fill.
    const agent = await Agent.connect(b.url);
    const made = await agent.send({ method: "Target.createTarget", params: { url: `${origin}/account` } });
    const target = (made as { result?: { targetId?: string } }).result?.targetId!;
    await agent.send({ method: "Target.attachToTarget", params: { targetId: target, flatten: true } });

    const fill = await b.callTool(
      "request_fill",
      { binding_id: "acme", target_id: target, selector: "#password" },
      observe(target),
    );
    expect(fill).toMatchObject({ status: "filled" });

    // 3. Capture — while logged in, generate an API key and store it. The agent
    //    passes its tab (for the session) and the site id, nothing else.
    const cap = await b.callTool(
      "begin_credential_capture",
      { site_id: "acme-key", target_id: target },
      observe(target),
    );
    expect(cap).toMatchObject({ status: "captured", entryId: "acme-key" });
    // The key is in no agent-visible output.
    expect(issuedKey.length).toBeGreaterThan(10);
    expect(JSON.stringify(cap)).not.toContain(issuedKey);

    // The vault holds exactly the key the site issued, encrypted at rest.
    const raw = await readFile(vaultPath, "utf8");
    expect(raw).not.toContain(issuedKey);
    const doc = await openVault(JSON.parse(raw), PASSPHRASE);
    const entry = doc.entries.find((e) => e.id === "acme-key");
    expect(entry?.secret).toBe(issuedKey);

    agent.close();
  }, 120_000);
});

describe.skipIf(HAVE_CHROME)("register, log in, and capture a generated key", () => {
  it("is skipped because no Chromium was found", () => {
    expect(HAVE_CHROME).toBe(false);
  });
});
