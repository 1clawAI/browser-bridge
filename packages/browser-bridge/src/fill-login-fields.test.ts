// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * A fill against a real-shaped login form: the username is not pre-filled, and
 * the form submits only through a named button's click (a bare form.submit()
 * does nothing — the shape of an ASP.NET postback or a JS-bound button).
 *
 * The login-session test cheated on both counts — the username was a server-set
 * `value` and a form submit worked — so it could not have caught the two gaps a
 * live site (weatherapi.com) exposed: the fill typed only the password, and
 * submitted generically. This drives both `username`/`usernameSelector` and
 * `submitSelector` on the binding, and requires the agent's tab to end up
 * authenticated.
 */
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WebSocket } from "ws";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { startBridge, type BridgeHandle } from "./bridge.js";
import { LocalVaultDriver } from "./drivers/local.js";
import { sealVault } from "./drivers/local-vault-file.js";

const CHROME =
  process.env.ONECLAW_BRIDGE_CHROME ??
  { darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", linux: "/usr/bin/google-chrome" }[
    process.platform as "darwin" | "linux"
  ] ??
  "";
const HAVE_CHROME = CHROME !== "" && existsSync(CHROME);
const PASSPHRASE = "a-long-enough-passphrase";
const USER = "ada@example.com";
const PASSWORD = "hunter2-fields-test!";
const ARGS = ["--headless=new", ...(process.env.CI && process.platform === "linux" ? ["--no-sandbox", "--disable-dev-shm-usage"] : [])];

let server: Server;
let origin = "";

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const signedIn = (req.headers.cookie ?? "").includes("session=ada");
    if (url.pathname === "/login") {
      // No <form>. The button carries the whole login in a click handler, so a
      // generic form submit cannot work — only clicking #signin does.
      res.writeHead(200, { "content-type": "text/html" }).end(`<!doctype html><body>
        <input id="user" placeholder="username">
        <input id="pass" type="password">
        <button id="signin" onclick="
          const u=document.getElementById('user').value, p=document.getElementById('pass').value;
          location.href='/session?u='+encodeURIComponent(u)+'&p='+encodeURIComponent(p);">Sign in</button>
        </body>`);
      return;
    }
    if (url.pathname === "/session") {
      const ok = url.searchParams.get("u") === USER && url.searchParams.get("p") === PASSWORD;
      if (!ok) return void res.writeHead(302, { location: "/login?bad=1" }).end();
      return void res.writeHead(302, { location: "/account", "set-cookie": "session=ada; Path=/" }).end();
    }
    if (url.pathname === "/account") {
      return void res
        .writeHead(signedIn ? 200 : 401, { "content-type": "text/html" })
        .end(`<!doctype html><body><div id="who">${signedIn ? USER : "anonymous"}</div></body>`);
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

class Agent {
  #ws: WebSocket;
  #n = 1;
  readonly #p = new Map<number, (m: Record<string, unknown>) => void>();
  private constructor(ws: WebSocket) {
    this.#ws = ws;
    this.#ws.on("message", (d) => {
      const m = JSON.parse(String(d)) as { id?: number };
      if (typeof m.id === "number") { this.#p.get(m.id)?.(m as Record<string, unknown>); this.#p.delete(m.id); }
    });
  }
  static async connect(url: string) {
    const ws = new WebSocket(url);
    await new Promise((res, rej) => { ws.once("open", res); ws.once("error", rej); });
    return new Agent(ws);
  }
  send(m: Record<string, unknown>): Promise<Record<string, unknown>> {
    const id = this.#n++;
    return new Promise((r) => { this.#p.set(id, r); this.#ws.send(JSON.stringify({ id, ...m })); });
  }
  close() { this.#ws.close(); }
}

let bridge: BridgeHandle | undefined;
afterEach(async () => { await bridge?.close(); bridge = undefined; });

describe.skipIf(!HAVE_CHROME)("a fill on a form with an empty username and a button-only submit", () => {
  it("types the username, clicks the button, and logs the agent in", async () => {
    const dir = mkdtempSync(join(tmpdir(), "1claw-fields-"));
    const path = join(dir, "vault.json");
    writeFileSync(
      path,
      JSON.stringify(
        await sealVault(
          [{
            id: "acme", secret: PASSWORD, loginUrl: `${origin}/login`, allowedHosts: ["127.0.0.1"],
            username: USER, usernameSelector: "#user", submitSelector: "#signin",
          }],
          PASSPHRASE,
        ),
      ),
    );
    const backend = new LocalVaultDriver({ path, passphrase: PASSPHRASE });
    await backend.open();
    bridge = await startBridge({ executablePath: CHROME, backend, host: "127.0.0.1", port: 0, args: ARGS });

    const agent = await Agent.connect(bridge.url);
    const made = await agent.send({ method: "Target.createTarget", params: { url: `${origin}/account` } });
    const target = (made as { result?: { targetId?: string } }).result?.targetId!;
    const att = await agent.send({ method: "Target.attachToTarget", params: { targetId: target, flatten: true } });
    const session = (att as { result?: { sessionId?: string } }).result?.sessionId!;
    const who = async () => {
      for (let i = 0; i < 60; i++) {
        const out = await agent.send({ sessionId: session, method: "Runtime.evaluate", params: { expression: "document.querySelector('#who')?.textContent ?? ''", returnByValue: true } });
        const v = (out as { result?: { result?: { value?: string } } }).result?.result?.value ?? "";
        if (v) return v;
        await new Promise((r) => setTimeout(r, 150));
      }
      return "";
    };
    expect(await who()).toBe("anonymous");

    const fill = await bridge.callTool(
      "request_fill",
      { binding_id: "acme", target_id: target, selector: "#pass" },
      () => ({ tabOrigin: origin, frameOrigin: origin, formActionOrigin: origin, frameId: target, generation: 0 }),
    );
    expect(fill).toMatchObject({ status: "filled" });
    expect(JSON.stringify(fill)).not.toContain(PASSWORD);

    await agent.send({ sessionId: session, method: "Page.reload" });
    expect(await who()).toBe(USER);
    agent.close();
  }, 120_000);
});

describe.skipIf(HAVE_CHROME)("a fill on a form with an empty username and a button-only submit", () => {
  it("is skipped because no Chromium was found", () => { expect(HAVE_CHROME).toBe(false); });
});
