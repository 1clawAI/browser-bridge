#!/usr/bin/env node
// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * The whole thing, and the agent sees no secret at any step:
 *
 *   1. register    — the bridge signs up and generates the password
 *   2. log in       — the bridge fills and submits; the agent's tab is authed
 *   3. capture      — while logged in, the bridge generates an API key on the
 *                     site, reads it, and stores it in the vault
 *   4. execute      — the agent runs an intent that uses the captured key in a
 *                     real request; a local executor injects it, the agent gets
 *                     the response
 *
 * Steps 1-3 are browser-bridge. Step 4 is a stand-in for the 1Claw Execution
 * Intents API (see examples/intent-executor.mjs): the credential is used
 * without the agent ever holding it.
 *
 *   node examples/full-flow-capture.mjs [--chrome /path/to/chrome]
 */
import { createServer } from "node:http";
import { existsSync, mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startBridge, LocalVaultDriver, sealVault, openVault } from "../dist/index.js";
import { Agent } from "./agent.mjs";
import { executeIntent } from "./intent-executor.mjs";

const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf(`--${n}`); return i > -1 ? argv[i + 1] : undefined; };
const CHROME =
  flag("chrome") ?? process.env.ONECLAW_BRIDGE_CHROME ??
  { darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", linux: "/usr/bin/google-chrome" }[process.platform];
if (!CHROME || !existsSync(CHROME)) { console.error(`No Chromium at ${CHROME ?? "(unknown)"}. Pass --chrome.`); process.exit(2); }
const PASSPHRASE = "a-long-enough-demo-passphrase";

// ── A site: signup, login, an API-keys page, and a key-protected endpoint ────
const users = new Map();
let issuedKey = "";
const bodyOf = (req) => new Promise((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
const site = createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  const signedIn = (req.headers.cookie ?? "").includes("session=ada");
  if (u.pathname === "/signup" && req.method === "GET")
    return void res.end(`<!doctype html><body><form action="/signup" method="post"><input id="email" name="email"><input id="password" name="password" type="password"><button id="go" type="submit">Go</button></form></body>`);
  if (u.pathname === "/signup" && req.method === "POST") { const p = new URLSearchParams(await bodyOf(req)); users.set(p.get("email"), p.get("password") || ""); return void res.writeHead(302, { location: "/welcome" }).end(); }
  if (u.pathname === "/welcome") return void res.end("<!doctype html><h1 id=ok>Welcome</h1>");
  if (u.pathname === "/login" && req.method === "GET")
    return void res.end(`<!doctype html><body><form action="/session" method="post"><input id="username" name="username" value="ada@example.com"><input id="password" name="password" type="password"></form></body>`);
  if (u.pathname === "/session" && req.method === "POST") { const p = new URLSearchParams(await bodyOf(req)); if (users.get(p.get("username")) !== p.get("password")) return void res.writeHead(302, { location: "/login?bad=1" }).end(); return void res.writeHead(302, { location: "/account", "set-cookie": "session=ada; Path=/" }).end(); }
  if (u.pathname === "/account") return void res.writeHead(signedIn ? 200 : 401, { "content-type": "text/html" }).end(`<!doctype html><body><div id="who">${signedIn ? "ada@example.com" : "anonymous"}</div></body>`);
  if (u.pathname === "/settings/api") {
    if (!signedIn) return void res.writeHead(401).end("no");
    return void res.writeHead(200, { "content-type": "text/html" }).end(`<!doctype html><body><input id="api-key" value=""><button id="generate">Generate</button><script>document.getElementById('generate').addEventListener('click',async()=>{const r=await fetch('/issue-key',{method:'POST',credentials:'include'});document.getElementById('api-key').value=(await r.json()).key;});</script></body>`);
  }
  if (u.pathname === "/issue-key" && req.method === "POST") { if (!signedIn) return void res.writeHead(401).end("no"); issuedKey = "sk_live_" + Math.abs(Date.now() ^ (Math.random() * 1e9 | 0)).toString(36); return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ key: issuedKey })); }
  // A key-protected "weather" endpoint — the thing step 4 calls with the key.
  if (u.pathname === "/api/weather") {
    if (u.searchParams.get("key") !== issuedKey) return void res.writeHead(401).end('{"error":"bad key"}');
    return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ city: u.searchParams.get("q"), tempC: 17 }));
  }
  res.writeHead(404).end();
});
await new Promise((r) => site.listen(0, "127.0.0.1", r));
const origin = `http://127.0.0.1:${site.address().port}`;

// ── Vault: a signup policy and a capture policy, both human-authored ─────────
const dir = mkdtempSync(join(tmpdir(), "1claw-fullcap-"));
const vaultPath = join(dir, "vault.json");
writeFileSync(vaultPath, JSON.stringify(await sealVault({
  entries: [],
  registrations: [{ id: "acme", signupUrl: `${origin}/signup`, loginUrl: `${origin}/login`, username: "ada@example.com", allowedHosts: ["127.0.0.1"], usernameSelector: "#email", passwordSelector: "#password", submitSelector: "#go", success: { urlChanges: true } }],
  captures: [{ id: "acme-key", captureUrl: `${origin}/settings/api`, loginUrl: `${origin}/login`, allowedHosts: ["127.0.0.1"], generateSelector: "#generate", valueSelector: "#api-key", valueProp: "value" }],
}, PASSPHRASE)));

const backend = new LocalVaultDriver({ path: vaultPath, passphrase: PASSPHRASE });
await backend.open();
const bridge = await startBridge({ executablePath: CHROME, backend, host: "127.0.0.1", port: 0, args: ["--headless=new"] });
const observe = (frameId) => () => ({ tabOrigin: origin, frameOrigin: origin, formActionOrigin: origin, frameId, generation: 0 });

try {
  console.log(`\n  site:   ${origin}\n  bridge: ${bridge.url}\n  tools:  ${bridge.tools.map((t) => t.name).join(", ")}\n`);

  const reg = await bridge.callTool("begin_credential_registration", { site_id: "acme" }, observe("acme"));
  console.log(`  1. register        -> ${JSON.stringify(reg)}`);

  const agent = await Agent.connect(bridge.url);
  const { targetId, sessionId } = await agent.openTab(`${origin}/account`);
  const who = async () => { for (let i = 0; i < 60; i++) { const v = await agent.evaluate(sessionId, "document.querySelector('#who')?.textContent ?? ''"); if (v) return v; await new Promise((r) => setTimeout(r, 150)); } return ""; };
  console.log(`  2. before login    -> ${await who()}`);

  const fill = await bridge.callTool("request_fill", { binding_id: "acme", target_id: targetId, selector: "#password" }, observe(targetId));
  await agent.reload(sessionId);
  console.log(`     login fill      -> ${JSON.stringify(fill)}; agent tab now: ${await who()}`);

  const cap = await bridge.callTool("begin_credential_capture", { site_id: "acme-key", target_id: targetId }, observe(targetId));
  console.log(`  3. capture key     -> ${JSON.stringify(cap)}`);

  // 4. Execution intent: the agent asks to run a request that needs the key.
  //    It passes params (the city), never the key. The executor injects it.
  const result = await executeIntent({
    vaultPath, passphrase: PASSPHRASE,
    binding: { method: "GET", url: `${origin}/api/weather?q={{city}}`, secretEntryId: "acme-key", inject: { as: "query", name: "key" } },
    params: { city: "London" },
  });
  console.log(`  4. execute intent  -> HTTP ${result.status}, body ${result.body}`);

  const key = openVault(JSON.parse(readFileSync(vaultPath, "utf8")), PASSPHRASE).then((d) => d.entries.find((e) => e.id === "acme-key")?.secret);
  const storedKey = await key;
  const agentSaw = [reg, fill, cap, result].some((r) => JSON.stringify(r).includes(storedKey));
  const ok = reg.status === "registered" && fill.status === "filled" && cap.status === "captured" && result.status === 200 && JSON.parse(result.body).tempC === 17 && !agentSaw;
  console.log(`\n  agent ever saw the key: ${agentSaw ? "YES — BUG" : "no"}`);
  console.log(`  ${ok ? "OK" : "FAILED"}: registered, logged in, captured a key, and used it — the agent never saw it\n`);
  agent.close();
  process.exitCode = ok ? 0 : 1;
} finally {
  await bridge.close();
  await new Promise((r) => site.close(r));
}
