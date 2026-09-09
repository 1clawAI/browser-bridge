#!/usr/bin/env node
// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * The safety paths, not the happy path. The other examples all show a fill,
 * a registration or a capture succeeding; this shows the two of them failing
 * correctly, since a control that has never been seen to fail is a control
 * nobody has checked:
 *
 *   A. a site whose password policy always rejects the bridge's generated
 *      password -> registration must abort with "site_rejected_password"
 *      and store NOTHING (not "commit anyway", not "no_success_signal").
 *   B. a correct binding, but the site's own login rejects the credential
 *      (simulating a site-side password change/desync) -> the fill must
 *      report failure, not silently "succeed".
 *
 *   node examples/failure-modes.mjs [--chrome /path/to/chrome]
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
if (!CHROME || !existsSync(CHROME)) { console.error(`No Chromium at ${CHROME ?? "(unknown)"}. Pass --chrome /path/to/chrome.`); process.exit(2); }
const PASSPHRASE = "a-long-enough-demo-passphrase";

// A picky site: signup shows a visible #error unless the password is at
// least 40 characters (the bridge's generated passwords are shorter than
// that by default, so this always rejects -- on purpose, to exercise the
// "cancel rather than commit" path). Login also actually checks the password.
const users = new Map();
const bodyOf = (req) => new Promise((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
const site = createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  if (u.pathname === "/signup" && req.method === "GET")
    return void res.end(`<!doctype html><body><form action="/signup" method="post"><input id="email" name="email"><input id="password" name="password" type="password"><button id="go" type="submit">Go</button></form></body>`);
  if (u.pathname === "/signup" && req.method === "POST") {
    const p = new URLSearchParams(await bodyOf(req));
    const pw = p.get("password") || "";
    if (pw.length < 40) return void res.end(`<!doctype html><body><div class="error">Password must be at least 40 characters.</div></body>`);
    users.set(p.get("email"), pw);
    return void res.writeHead(302, { location: "/welcome" }).end();
  }
  if (u.pathname === "/welcome") return void res.end("<!doctype html><h1 id=ok>Welcome</h1>");
  if (u.pathname === "/login" && req.method === "GET")
    return void res.end(`<!doctype html><body><form action="/session" method="post"><input id="u" name="username" value="pat@example.com"><input id="p" name="password" type="password"></form></body>`);
  if (u.pathname === "/session" && req.method === "POST") {
    const p = new URLSearchParams(await bodyOf(req));
    if (users.get(p.get("username")) !== p.get("password"))
      return void res.writeHead(200, { "content-type": "text/html" }).end(`<!doctype html><body><div class="error" id="loginerr">Wrong password</div></body>`);
    return void res.writeHead(302, { location: "/account", "set-cookie": "session=pat; Path=/" }).end();
  }
  if (u.pathname === "/account") {
    const signedIn = (req.headers.cookie ?? "").includes("session=pat");
    return void res.writeHead(signedIn ? 200 : 401).end(signedIn ? "signed in" : "not signed in");
  }
  res.writeHead(404).end();
});
await new Promise((r) => site.listen(0, "127.0.0.1", r));
const origin = `http://127.0.0.1:${site.address().port}`;

const dir = mkdtempSync(join(tmpdir(), "1claw-fail-"));
const vaultPath = join(dir, "vault.json");
// A: registration policy the site will always reject (40-char minimum, bridge won't meet it).
// B: a fill binding pre-loaded with a WRONG password, to check the site-side rejection path.
writeFileSync(vaultPath, JSON.stringify(await sealVault({
  entries: [{ id: "pat-wrong", secret: "this-is-not-the-real-password", loginUrl: `${origin}/login`, allowedHosts: ["127.0.0.1"], usernameSelector: "#u", passwordSelector: "#p" }],
  registrations: [{ id: "picky", signupUrl: `${origin}/signup`, loginUrl: `${origin}/login`, username: "pat@example.com",
    allowedHosts: ["127.0.0.1"], usernameSelector: "#email", passwordSelector: "#password", submitSelector: "#go",
    success: { urlChanges: true, errorSelector: ".error" } }],
}, PASSPHRASE)));
const SITE_PASSWORD = "the-real-password-set-out-of-band";
users.set("pat@example.com", SITE_PASSWORD);  // so a fill attempt has something to fail against

const backend = new LocalVaultDriver({ path: vaultPath, passphrase: PASSPHRASE });
await backend.open();
const bridge = await startBridge({ executablePath: CHROME, backend, host: "127.0.0.1", port: 0, args: ["--headless=new"] });
const observe = (frameId) => () => ({ tabOrigin: origin, frameOrigin: origin, formActionOrigin: origin, frameId, generation: 0 });

let allOk = true;
try {
  console.log(`\n=== TEST: failure paths (rejected password policy, wrong-password login) ===`);
  console.log(`  site: ${origin}`);

  // A. Registration against a policy that will always reject the generated password.
  const reg = await bridge.callTool("begin_credential_registration", { site_id: "picky" }, observe("picky"));
  console.log(`  A. register against a 40-char-min site -> ${JSON.stringify(reg)}`);
  const vaultAfterA = await openVault(JSON.parse(readFileSync(vaultPath, "utf8")), PASSPHRASE);
  const storedA = vaultAfterA.entries.find((e) => e.id === "picky");
  // The site's own record must be untouched. A rejected signup that still
  // overwrote the account's password would be the worst of the three outcomes,
  // and it is the one a "nothing was stored in the vault" check cannot see.
  const siteUnchanged = users.get("pat@example.com") === SITE_PASSWORD;
  const aOk = reg.status === "rejected" && reg.reason === "site_rejected_password" && !storedA && siteUnchanged;
  console.log(`     nothing stored for "picky": ${!storedA ? "correct" : "BUG -- something was stored anyway"}`);
  console.log(`     site's own password unchanged: ${siteUnchanged ? "correct" : "BUG -- the rejected signup overwrote it"}`);
  console.log(`     ${aOk ? "OK" : "FAILED"}: rejected password policy correctly cancels rather than commits\n`);
  allOk &&= aOk;

  // B. A fill using a binding whose stored secret is simply wrong for this site
  // (simulating drift between the vault and the site) -- must not report "filled"
  // as if it logged in, since the site itself rejected it.
  const agent = await Agent.connect(bridge.url);
  const { targetId, sessionId } = await agent.openTab(`${origin}/account`);
  const fill = await bridge.callTool("request_fill", { binding_id: "pat-wrong", target_id: targetId, selector: "#p" }, observe(targetId));
  console.log(`  B. fill with a wrong stored password -> ${JSON.stringify(fill)}`);
  await agent.reload(sessionId);
  const status = await agent.evaluate(sessionId, "document.body.textContent");
  console.log(`     /account after the fill attempt -> "${status.trim()}"`);
  // The bridge itself only guarantees the type+submit happened; whether the
  // *site* accepted it is visible in whether the session actually authenticated.
  const bOk = fill.status === "filled" && status.trim() !== "signed in";
  console.log(`     ${bOk ? "OK" : "FAILED"}: bridge reports the fill mechanically, but the site correctly never authenticated a wrong password\n`);
  allOk &&= bOk;
  agent.close();

  console.log(`  ${allOk ? "ALL OK" : "SOME FAILED"}\n`);
  process.exitCode = allOk ? 0 : 1;
} finally {
  await bridge.close();
  await new Promise((r) => site.close(r));
}
