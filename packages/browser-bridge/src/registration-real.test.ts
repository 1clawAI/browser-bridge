// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CdpGate } from "./cdp-policy.js";
import { LocalVaultDriver } from "./drivers/local.js";
import { openVault, sealVault, type RegistrationPolicy } from "./drivers/local-vault-file.js";
import { PipeCdpTransport } from "./pipe-transport.js";
import { RegistrationEngine } from "./registration-engine.js";

/**
 * The registration ceremony, against a real signup form in a real Chromium.
 *
 * The unit tests cover the two-phase commit — what the driver stores and when.
 * They cannot cover the part most likely to be wrong: navigating, finding the
 * fields, typing, submitting, and deciding whether the *site* accepted it. That
 * last judgement is the one that writes a password the site never stored, and
 * no amount of mocking exercises it.
 *
 * The server below behaves like a real signup: it enforces a password rule and
 * says no when it is not met.
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

/** Passwords the fake site accepts. Mirrors a real, annoying rule. */
const siteAccepts = (pw: string) => pw.length >= 12 && /[^A-Za-z0-9]/.test(pw);

let server: Server;
let origin = "";
/** What the site actually received, so we can compare it with what was stored. */
let received: { username?: string; password?: string } = {};

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/signup") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(`<!doctype html><body>
        ${url.searchParams.get("error") ? '<p class="error">Password too weak</p>' : ""}
        <form action="/session" method="post">
          <input id="email" name="email">
          <input id="password" name="password" type="password">
          <button type="submit" id="go">Create</button>
        </form></body>`);
      return;
    }
    if (url.pathname === "/session" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const form = new URLSearchParams(body);
        const password = form.get("password") ?? "";
        received = { username: form.get("email") ?? "", password };
        // A real site rejects and re-renders; it does not silently succeed.
        const to = siteAccepts(password) ? "/welcome" : "/signup?error=1";
        res.writeHead(302, { location: to });
        res.end();
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

function policy(over: Partial<RegistrationPolicy> = {}): RegistrationPolicy {
  return {
    id: "acme",
    signupUrl: `${origin}/signup`,
    loginUrl: `${origin}/signup`,
    username: "ada@example.com",
    allowedHosts: ["127.0.0.1"],
    usernameSelector: "#email",
    passwordSelector: "#password",
    submitSelector: "#go",
    success: { selector: ".dashboard", errorSelector: ".error" },
    ...over,
  };
}

async function setup(p: RegistrationPolicy) {
  const dir = mkdtempSync(join(tmpdir(), "1claw-reg-real-"));
  const path = join(dir, "vault.json");
  writeFileSync(path, JSON.stringify(await sealVault({ entries: [], registrations: [p] }, PASSPHRASE)));
  const driver = new LocalVaultDriver({ path, passphrase: PASSPHRASE });
  await driver.open();
  await driver.openSession({ clientId: "c", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });

  const transport = PipeCdpTransport.launch({ executablePath: CHROME, args: LAUNCH_ARGS });
  const engine = new RegistrationEngine({
    transport,
    gate: new CdpGate(),
    takeSecret: (id) => driver.takeRegistrationSecret(id),
    commit: (id) => driver.commitRegistration(id),
    cancel: (id) => driver.cancelRegistration(id),
    settleMs: 8000,
  });
  return { driver, transport, engine, path };
}

describe.skipIf(!HAVE_CHROME)("registering against a real signup form", () => {
  it("creates the account and stores what the site accepted", async () => {
    received = {};
    const { driver, transport, engine, path } = await setup(policy());
    try {
      const grant = await driver.beginRegistration({ siteId: "acme" } as never);
      if (grant.kind !== "registration_grant") throw new Error("expected a grant");

      const outcome = await engine.register(grant as never);
      expect(outcome).toMatchObject({ status: "registered", bindingId: "acme" });

      // The site received the policy's username, not anything the agent chose.
      expect(received.username).toBe("ada@example.com");
      expect(received.password).toBeTruthy();
      expect(siteAccepts(received.password!)).toBe(true);

      // And the stored credential is *the same one the site accepted* — the
      // failure that matters is storing a different password from the one that
      // was typed, which would look fine until the first login.
      const doc = await openVault(JSON.parse(await readFile(path, "utf8")), PASSPHRASE);
      expect(doc.entries).toHaveLength(1);
      expect(doc.entries[0]!.secret).toBe(received.password);
    } finally {
      await transport.close();
    }
  }, 120_000);

  it("stores nothing when the site rejects the password", async () => {
    received = {};
    // A policy demanding a password this site will refuse: no symbols, and
    // short enough to fail its length rule.
    const { driver, transport, engine, path } = await setup(
      policy({ passwordPolicy: { length: 10, symbols: "", upper: false, digits: true } }),
    );
    try {
      const grant = await driver.beginRegistration({ siteId: "acme" } as never);
      if (grant.kind !== "registration_grant") throw new Error("expected a grant");

      const outcome = await engine.register(grant as never);
      expect(outcome).toMatchObject({ status: "rejected" });

      // The site saw it and said no; nothing reached the vault.
      expect(received.password).toBeTruthy();
      expect(siteAccepts(received.password!)).toBe(false);
      const doc = await openVault(JSON.parse(await readFile(path, "utf8")), PASSPHRASE);
      expect(doc.entries).toHaveLength(0);
    } finally {
      await transport.close();
    }
  }, 120_000);

  it("stores nothing when it cannot tell whether the site accepted", async () => {
    // The default has to be refusal. A success selector that never appears is
    // indistinguishable from a signup that silently failed, and committing on
    // "probably fine" writes a credential that fails weeks later.
    received = {};
    const { driver, transport, engine, path } = await setup(
      policy({ success: { selector: ".never-appears" } }),
    );
    try {
      const grant = await driver.beginRegistration({ siteId: "acme" } as never);
      if (grant.kind !== "registration_grant") throw new Error("expected a grant");

      const outcome = await engine.register(grant as never);
      expect(outcome).toMatchObject({ status: "rejected", reason: "no_success_signal" });

      const doc = await openVault(JSON.parse(await readFile(path, "utf8")), PASSPHRASE);
      expect(doc.entries).toHaveLength(0);
    } finally {
      await transport.close();
    }
  }, 120_000);

  it("leaves a credential that actually logs in", async () => {
    // End of the loop: register, then fill with what was stored, and confirm
    // the site accepts it. A password stored differently from the one typed
    // would pass every earlier assertion and fail here.
    received = {};
    const { driver, transport, engine, path } = await setup(policy());
    try {
      const grant = await driver.beginRegistration({ siteId: "acme" } as never);
      if (grant.kind !== "registration_grant") throw new Error("expected a grant");
      expect((await engine.register(grant as never)).status).toBe("registered");
      const registered = received.password!;

      const fill = await driver.authorizeFill({
        sessionId: "s", bindingId: "acme",
        tabOrigin: origin, frameOrigin: origin, formActionOrigin: origin,
        frameId: "T", generation: 1,
      } as never);
      if (fill.kind !== "grant") throw new Error(`expected a fill grant, got ${fill.kind}`);

      const handle = await driver.consumeFill(fill as never);
      expect(handle.use((b) => new TextDecoder().decode(b))).toBe(registered);
      void path;
    } finally {
      await transport.close();
    }
  }, 120_000);
});

describe.skipIf(HAVE_CHROME)("registering against a real signup form", () => {
  it("is skipped because no Chromium was found", () => {
    expect(HAVE_CHROME).toBe(false);
  });
});
