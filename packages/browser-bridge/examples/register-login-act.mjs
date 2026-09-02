#!/usr/bin/env node
// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * The whole story, end to end, with no account and no network:
 *
 *   1. create an account   — the bridge signs up and generates the password
 *   2. store the password  — it lands in the community vault, encrypted
 *   3. log in with it       — the bridge fills and submits; the session cookie
 *                             lands in the AGENT's own browser context
 *   4. act as that user     — the agent updates a profile, authenticated
 *
 * The agent never sees the password at any step. It supplies one thing the
 * whole way through: which pre-authorised site. Everything else — the signup
 * and login URLs, the username, the form selectors, the generated secret —
 * comes from a policy a human wrote and from the vault, never from the agent.
 *
 *   node examples/register-login-act.mjs [--chrome /path/to/chrome]
 */
import { createServer } from "node:http";
import { existsSync, mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startBridge, LocalVaultDriver, sealVault, openVault } from "../dist/index.js";
import { Agent } from "./agent.mjs";

const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf(`--${n}`); return i > -1 ? argv[i + 1] : undefined; };
const CHROME =
  flag("chrome") ??
  process.env.ONECLAW_BRIDGE_CHROME ??
  { darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    linux: "/usr/bin/google-chrome" }[process.platform];
if (!CHROME || !existsSync(CHROME)) {
  console.error(`No Chromium at ${CHROME ?? "(unknown)"}. Pass --chrome /path/to/chrome.`);
  process.exit(2);
}
const PASSPHRASE = "a-long-enough-demo-passphrase";

// ── A site to register with, log into, and act on ───────────────────────────
// A tiny app: signup creates an account, login sets a session cookie, /account
// reflects who you are, and /profile records an update only when signed in.
const users = new Map();     // email -> password (the site's own store)
const profileUpdates = [];
const bodyOf = (req) => new Promise((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
const site = createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const signedIn = (req.headers.cookie ?? "").includes("session=ada");
  if (url.pathname === "/signup" && req.method === "GET")
    return void res.end(`<!doctype html><body><form action="/signup" method="post">
      <input id="email" name="email"><input id="password" name="password" type="password">
      <button id="go" type="submit">Sign up</button></form></body>`);
  if (url.pathname === "/signup" && req.method === "POST") {
    const p = new URLSearchParams(await bodyOf(req));
    users.set(p.get("email"), p.get("password") || "");
    return void res.writeHead(302, { location: "/welcome" }).end();  // URL change = success
  }
  if (url.pathname === "/welcome") return void res.end("<!doctype html><h1 id=ok>Welcome</h1>");
  if (url.pathname === "/login" && req.method === "GET")
    return void res.end(`<!doctype html><body><form action="/session" method="post">
      <input id="username" name="username" value="ada@example.com">
      <input id="password" name="password" type="password"></form></body>`);
  if (url.pathname === "/session" && req.method === "POST") {
    const p = new URLSearchParams(await bodyOf(req));
    if (users.get(p.get("username")) !== p.get("password"))
      return void res.writeHead(302, { location: "/login?bad=1" }).end();
    return void res.writeHead(302, { location: "/account", "set-cookie": "session=ada; Path=/" }).end();
  }
  if (url.pathname === "/account")
    return void res.writeHead(signedIn ? 200 : 401, { "content-type": "text/html" })
      .end(`<!doctype html><body><div id="who">${signedIn ? "ada@example.com" : "anonymous"}</div></body>`);
  if (url.pathname === "/profile" && req.method === "POST") {
    if (!signedIn) return void res.writeHead(401).end("not signed in");
    profileUpdates.push(new URLSearchParams(await bodyOf(req)).get("display_name") ?? "");
    return void res.writeHead(200).end("ok");
  }
  res.writeHead(404).end();
});
await new Promise((r) => site.listen(0, "127.0.0.1", r));
const origin = `http://127.0.0.1:${site.address().port}`;

// ── The vault: a signup policy a human authored. The agent chooses none of it.
const dir = mkdtempSync(join(tmpdir(), "1claw-example-"));
const vaultPath = join(dir, "vault.json");
writeFileSync(vaultPath, JSON.stringify(await sealVault({ entries: [], registrations: [{
  id: "acme",
  signupUrl: `${origin}/signup`,
  loginUrl: `${origin}/login`,
  username: "ada@example.com",
  allowedHosts: ["127.0.0.1"],
  usernameSelector: "#email",
  passwordSelector: "#password",
  submitSelector: "#go",
  success: { urlChanges: true },
}] }, PASSPHRASE)));

const backend = new LocalVaultDriver({ path: vaultPath, passphrase: PASSPHRASE });
await backend.open();
const bridge = await startBridge({ executablePath: CHROME, backend, host: "127.0.0.1", args: ["--headless=new"] });

// The bridge reads live page state itself in a deployment; the examples pass a
// snapshot so they need no live agent frame for the origin checks.
const observe = (frameId) => () => ({ tabOrigin: origin, frameOrigin: origin, formActionOrigin: origin, frameId, generation: 0 });

try {
  console.log(`  site:   ${origin}`);
  console.log(`  bridge: ${bridge.url}`);
  console.log(`  tools:  ${bridge.tools.map((t) => t.name).join(", ")}\n`);

  // 1 + 2. Create the account and store the password. Agent's only input: site.
  const reg = await bridge.callTool("begin_credential_registration", { site_id: "acme" }, observe("acme"));
  console.log(`  1. register          -> ${JSON.stringify(reg)}`);
  const stored = (await openVault(JSON.parse(readFileSync(vaultPath, "utf8")), PASSPHRASE))
    .entries.find((e) => e.id === "acme")?.secret;
  const rawVault = readFileSync(vaultPath, "utf8");
  console.log(`     password stored, ${stored?.length}-char, encrypted in the vault (cleartext in file: ${rawVault.includes(stored) ? "YES — BUG" : "no"})`);

  // The agent connects the way a framework does, and opens its own tab.
  const agent = await Agent.connect(bridge.url);
  const refused = await agent.send({ method: "Target.createBrowserContext" });
  console.log(`  2. agent self-context -> ${refused.error ? "refused (good)" : "ALLOWED — BUG"}`);
  const { targetId, sessionId } = await agent.openTab(`${origin}/account`);
  const whoWhen = async (want) => {
    for (let i = 0; i < 60; i++) {
      if ((await agent.evaluate(sessionId, "document.querySelector('#who')?.textContent ?? ''")) === want) return want;
      await new Promise((r) => setTimeout(r, 150));
    }
    return agent.evaluate(sessionId, "document.querySelector('#who')?.textContent ?? ''");
  };
  console.log(`  3. before login       -> ${await whoWhen("anonymous")}`);

  // 3. Log in. The bridge fills and submits; the agent never sees the value.
  const fill = await bridge.callTool("request_fill",
    { binding_id: "acme", target_id: targetId, selector: "#password" }, observe(targetId));
  console.log(`  4. login fill         -> ${JSON.stringify(fill)}`);
  await agent.reload(sessionId);
  const after = await whoWhen("ada@example.com");
  console.log(`  5. after login        -> ${after}`);

  // 4. Act as the logged-in user.
  const status = await agent.evaluate(sessionId,
    `fetch('/profile',{method:'POST',credentials:'include',headers:{'content-type':'application/x-www-form-urlencoded'},body:'display_name=Ada+Lovelace'}).then(r=>r.status)`,
    true);
  console.log(`  6. update profile     -> HTTP ${status}, server recorded ${JSON.stringify(profileUpdates)}`);

  const leaked = [JSON.stringify(reg), JSON.stringify(fill)].some((s) => stored && s.includes(stored));
  const ok = reg.status === "registered" && fill.status === "filled" && after === "ada@example.com" && profileUpdates[0] === "Ada Lovelace" && !leaked;
  console.log(`\n  agent ever saw the password: ${leaked ? "YES — BUG" : "no"}`);
  console.log(`  ${ok ? "OK" : "FAILED"}: registered, logged in, and acted — the agent never saw the password\n`);
  agent.close();
  process.exitCode = ok ? 0 : 1;
} finally {
  await bridge.close();
  await new Promise((r) => site.close(r));
}
