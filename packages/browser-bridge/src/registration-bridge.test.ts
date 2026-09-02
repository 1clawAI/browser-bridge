// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { startBridge, type BridgeHandle } from "./bridge.js";
import { LocalVaultDriver } from "./drivers/local.js";
import { openVault, sealVault, type RegistrationPolicy } from "./drivers/local-vault-file.js";

/**
 * Registration through `startBridge`, the entry point a real deployment uses.
 *
 * The engine tests drive `RegistrationEngine` directly. That leaves the same
 * gap that hid the `openSession` bug for a week: the composition root was
 * broken while thirty production assertions passed, because none of them went
 * through the bridge. A path that is only ever exercised in pieces is a path
 * nobody has run.
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
const LAUNCH_ARGS = [
  "--headless=new",
  ...(process.env.CI && process.platform === "linux"
    ? ["--no-sandbox", "--disable-dev-shm-usage"]
    : []),
];

let server: Server;
let origin = "";
let received: { username?: string; password?: string } = {};
/** Every path the site was asked for, so a redirected signup is visible. */
let visited: string[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    visited.push(url.pathname);
    if (url.pathname === "/signup" || url.pathname === "/elsewhere") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(`<!doctype html><body><form action="/session" method="post">
        <input id="email" name="email"><input id="password" name="password" type="password">
        <button type="submit" id="go">Create</button></form></body>`);
      return;
    }
    if (url.pathname === "/session" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const form = new URLSearchParams(body);
        received = { username: form.get("email") ?? "", password: form.get("password") ?? "" };
        res.writeHead(302, { location: "/welcome" }).end();
      });
      return;
    }
    if (url.pathname === "/welcome") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end('<!doctype html><body><div class="dashboard">Welcome</div></body>');
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

let bridge: BridgeHandle | undefined;
afterEach(async () => {
  await bridge?.close();
  bridge = undefined;
});

function policy(): RegistrationPolicy {
  return {
    id: "acme",
    signupUrl: `${origin}/signup`,
    loginUrl: `${origin}/signup`,
    username: "ada@example.com",
    allowedHosts: ["127.0.0.1"],
    usernameSelector: "#email",
    passwordSelector: "#password",
    submitSelector: "#go",
    success: { selector: ".dashboard" },
  };
}

async function start(registrations: RegistrationPolicy[]) {
  const dir = mkdtempSync(join(tmpdir(), "1claw-reg-bridge-"));
  const path = join(dir, "vault.json");
  writeFileSync(path, JSON.stringify(await sealVault({ entries: [], registrations }, PASSPHRASE)));
  const backend = new LocalVaultDriver({ path, passphrase: PASSPHRASE });
  await backend.open();
  bridge = await startBridge({
    executablePath: CHROME,
    backend,
    host: "127.0.0.1",
    port: 0,
    args: LAUNCH_ARGS,
  });
  return { bridge: bridge!, path };
}

const observe = () => ({
  tabOrigin: origin,
  frameOrigin: origin,
  formActionOrigin: origin,
  frameId: "agent-tab",
  generation: 0,
});

describe.skipIf(!HAVE_CHROME)("registration through the assembled bridge", () => {
  it("registers, and the agent's result carries no password", async () => {
    received = {};
    visited = [];
    const { bridge: b, path } = await start([policy()]);

    const result = await b.callTool(
      "begin_credential_registration",
      { site_id: "acme" },
      observe,
    );
    expect(result).toMatchObject({ status: "registered", bindingId: "acme" });

    // The whole claim, checked on the object the agent actually receives.
    expect(received.password).toBeTruthy();
    expect(JSON.stringify(result)).not.toContain(received.password!);

    const doc = await openVault(JSON.parse(await readFile(path, "utf8")), PASSPHRASE);
    expect(doc.entries[0]!.secret).toBe(received.password);
  }, 120_000);

  it("does not register the tool when no policy exists", async () => {
    // Absent, not disabled. A tool an agent can see is a tool it will call, and
    // a tool that always fails teaches it to retry.
    const { bridge: b } = await start([]);
    expect(b.tools.map((t) => t.name)).not.toContain("begin_credential_registration");

    const result = await b.callTool("begin_credential_registration", { site_id: "acme" }, observe);
    expect(result).toMatchObject({ status: "error" });
    expect(JSON.stringify(result)).toMatch(/unknown tool/i);
  }, 120_000);

  it("ignores a url the agent supplies, and signs up where the policy says", async () => {
    // The security property, through the real tool path. The schema says
    // additionalProperties: false, but schemas are advisory over MCP — what
    // matters is that nothing downstream reads these.
    received = {};
    visited = [];
    const { bridge: b } = await start([policy()]);

    const result = await b.callTool(
      "begin_credential_registration",
      {
        site_id: "acme",
        signup_url: `${origin}/elsewhere`,
        url: `${origin}/elsewhere`,
        username: "attacker@evil.test",
        password: "chosen-by-the-agent",
      },
      observe,
    );
    expect(result).toMatchObject({ status: "registered" });

    // It went to the policy's signup page, and never to the one the agent named.
    expect(visited).toContain("/signup");
    expect(visited).not.toContain("/elsewhere");
    // And used the policy's username, not the agent's.
    expect(received.username).toBe("ada@example.com");
    expect(received.password).not.toBe("chosen-by-the-agent");
  }, 120_000);

  it("refuses a site nobody authorised", async () => {
    const { bridge: b } = await start([policy()]);
    const result = await b.callTool("begin_credential_registration", { site_id: "evil" }, observe);
    expect(result).toMatchObject({ status: "denied" });
  }, 120_000);

  it("needs a site_id, and says so", async () => {
    const { bridge: b } = await start([policy()]);
    const result = await b.callTool("begin_credential_registration", {}, observe);
    expect(result).toMatchObject({ status: "error" });
    expect(JSON.stringify(result)).toMatch(/site_id/);
  }, 120_000);
});

describe.skipIf(HAVE_CHROME)("registration through the assembled bridge", () => {
  it("is skipped because no Chromium was found", () => {
    expect(HAVE_CHROME).toBe(false);
  });
});
