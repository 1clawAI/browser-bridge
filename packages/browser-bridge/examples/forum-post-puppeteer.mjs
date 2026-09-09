#!/usr/bin/env node
// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * A stock `puppeteer-core` client, not the hand-rolled Agent, driving a
 * different site shape (a forum) through a different activity (posting a
 * comment while authenticated) than the shipped examples cover.
 *
 * Two things worth knowing if you build on this:
 *
 *   - Playwright connects and navigates fine (framework-connect.test.ts
 *     proves that), but `context.newCDPSession(page)` calls
 *     `Target.attachToBrowserTarget` under the hood in `connectOverCDP` mode,
 *     which is not on the bridge's allowlist -- correctly refused, since it
 *     is broader than the per-target attach Puppeteer uses. Puppeteer exposes
 *     `page.target()._targetId` directly (via a normal `Target.attachToTarget`),
 *     which is why this example uses Puppeteer rather than Playwright.
 *   - `page.$eval`, `.type()` and other element-handle helpers go through
 *     `DOM.resolveNode`, also not on the allowlist (`DOM.querySelector` is,
 *     `resolveNode` is not). `page.evaluate()` -- pure `Runtime.evaluate` --
 *     works cleanly and is what every interaction below uses.
 *
 *   node examples/forum-post-puppeteer.mjs [--chrome /path/to/chrome]
 */
import { createServer } from "node:http";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startBridge, LocalVaultDriver, sealVault } from "../dist/index.js";
import puppeteer from "puppeteer-core";

const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf(`--${n}`); return i > -1 ? argv[i + 1] : undefined; };
const CHROME =
  flag("chrome") ??
  process.env.ONECLAW_BRIDGE_CHROME ??
  { darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    linux: "/usr/bin/google-chrome" }[process.platform];
if (!CHROME || !existsSync(CHROME)) { console.error(`No Chromium at ${CHROME ?? "(unknown)"}. Pass --chrome /path/to/chrome.`); process.exit(2); }
const PASSPHRASE = "a-long-enough-demo-passphrase";

const users = new Map();
const posts = [];
const bodyOf = (req) => new Promise((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
const site = createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  const signedIn = (req.headers.cookie ?? "").includes("session=grace");
  if (u.pathname === "/join" && req.method === "GET")
    return void res.end(`<!doctype html><body><form action="/join" method="post"><input id="handle" name="handle"><input id="pw" name="pw" type="password"><button id="create" type="submit">Join</button></form></body>`);
  if (u.pathname === "/join" && req.method === "POST") {
    const p = new URLSearchParams(await bodyOf(req));
    users.set(p.get("handle"), p.get("pw") || "");
    return void res.writeHead(302, { location: "/joined" }).end();
  }
  if (u.pathname === "/joined") return void res.end("<!doctype html><h1 id=ok>You're in</h1>");
  if (u.pathname === "/enter" && req.method === "GET")
    return void res.end(`<!doctype html><body><form action="/enter" method="post"><input id="h" name="handle" value="grace"><input id="p" name="pw" type="password"></form></body>`);
  if (u.pathname === "/enter" && req.method === "POST") {
    const p = new URLSearchParams(await bodyOf(req));
    if (users.get(p.get("handle")) !== p.get("pw")) return void res.writeHead(302, { location: "/enter?bad=1" }).end();
    return void res.writeHead(302, { location: "/forum", "set-cookie": "session=grace; Path=/" }).end();
  }
  if (u.pathname === "/forum")
    return void res.writeHead(200, { "content-type": "text/html" })
      .end(`<!doctype html><body><div id="who">${signedIn ? "grace" : "anonymous"}</div>${signedIn ? '<form id="postform"><textarea id="body"></textarea><button id="submit" type="button" onclick="fetch(\'/thread\',{method:\'POST\',credentials:\'include\',headers:{\'content-type\':\'application/x-www-form-urlencoded\'},body:\'body=\'+encodeURIComponent(document.getElementById(\'body\').value)}).then(()=>document.getElementById(\'status\').textContent=\'posted\')">Post</button><span id="status"></span></form>' : ""}</body>`);
  if (u.pathname === "/thread" && req.method === "POST") {
    if (!signedIn) return void res.writeHead(401).end("no");
    posts.push(new URLSearchParams(await bodyOf(req)).get("body") ?? "");
    return void res.writeHead(200).end("ok");
  }
  res.writeHead(404).end();
});
await new Promise((r) => site.listen(0, "127.0.0.1", r));
const origin = `http://127.0.0.1:${site.address().port}`;

const dir = mkdtempSync(join(tmpdir(), "1claw-forum-"));
const vaultPath = join(dir, "vault.json");
writeFileSync(vaultPath, JSON.stringify(await sealVault({
  entries: [], captures: [],
  registrations: [{ id: "forum", signupUrl: `${origin}/join`, loginUrl: `${origin}/enter`, username: "grace",
    allowedHosts: ["127.0.0.1"], usernameSelector: "#handle", passwordSelector: "#pw", submitSelector: "#create",
    success: { urlChanges: true } }],
}, PASSPHRASE)));

const backend = new LocalVaultDriver({ path: vaultPath, passphrase: PASSPHRASE });
await backend.open();
const bridge = await startBridge({ executablePath: CHROME, backend, host: "127.0.0.1", port: 0, args: ["--headless=new"] });
// NOTE: unlike the shipped examples (which drive their own hand-rolled Agent
// and so control every navigation), a real framework's page.goto() fires a
// genuine Page.frameNavigated that the bridge observes and bumps its own
// live per-target generation counter on -- the thing request_fill's TOCTOU
// check compares against. The examples' `generation: 0` stub only worked
// because their Agent never triggered that event before authorizing. Here we
// track it for real: one goto() = one bump.
let liveGeneration = 0;
const observe = (frameId) => () => ({ tabOrigin: origin, frameOrigin: origin, formActionOrigin: origin, frameId, generation: liveGeneration });

try {
  console.log(`\n=== TEST: forum site, real Puppeteer agent, post-while-authed activity ===`);
  console.log(`  site: ${origin}`);

  const reg = await bridge.callTool("begin_credential_registration", { site_id: "forum" }, observe("forum"));
  console.log(`  1. register  -> ${JSON.stringify(reg)}`);

  const browser = await puppeteer.connect({ browserWSEndpoint: bridge.url });
  const page = await browser.newPage();
  await page.goto(`${origin}/forum`);
  liveGeneration++;   // that goto() fired one real Page.frameNavigated
  const targetId = page.target()._targetId;
  // NOTE: page.$eval/page.type/element-handle APIs go through DOM.resolveNode
  // internally, which is NOT on the bridge's CDP allowlist (DOM.querySelector
  // is allowed, resolveNode is not -- a deliberate, narrower boundary than
  // Puppeteer/Playwright's convenience layer assumes). page.evaluate() (pure
  // Runtime.evaluate) works fine and is what the shipped examples use too, so
  // interaction below stays entirely inside evaluate() calls.
  console.log(`  2. before login -> ${await page.evaluate(() => document.querySelector("#who").textContent)}`);

  const fill = await bridge.callTool("request_fill",
    { binding_id: "forum", target_id: targetId, selector: "#p" }, observe(targetId));
  console.log(`  3. login fill -> ${JSON.stringify(fill)}`);
  await page.reload();
  console.log(`  4. after login -> ${await page.evaluate(() => document.querySelector("#who").textContent)}`);

  // 5. The activity: post a real comment, driven entirely by Puppeteer (via evaluate).
  await page.evaluate(() => { document.querySelector("#body").value = "Bridge posted this while authenticated, no password in sight."; });
  await page.evaluate(() => document.querySelector("#submit").click());
  await page.waitForFunction(() => document.querySelector("#status")?.textContent === "posted");
  console.log(`  5. post activity -> server recorded: ${JSON.stringify(posts)}`);

  const leaked = [JSON.stringify(reg), JSON.stringify(fill)].some((s) => s.includes(users.get("grace")));
  const ok = reg.status === "registered" && fill.status === "filled" && posts.length === 1 && !leaked;
  console.log(`\n  agent (Puppeteer) ever saw the password: ${leaked ? "YES -- BUG" : "no"}`);
  console.log(`  ${ok ? "OK" : "FAILED"}\n`);
  await browser.disconnect();
  process.exitCode = ok ? 0 : 1;
} finally {
  await bridge.close();
  await new Promise((r) => site.close(r));
}
