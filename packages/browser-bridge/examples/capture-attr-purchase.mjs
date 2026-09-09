#!/usr/bin/env node
// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * A third site (a shop with a payment-token settings page), the
 * attribute-based capture variant (`--value-attr` / `valueAttr`, for sites
 * that put the value in a data attribute rather than element text -- the
 * "copy button" pattern), and a "purchase" as the closing activity instead
 * of a profile or comment edit. Driven by a stock `puppeteer-core` client;
 * see `forum-post-puppeteer.mjs` for the framework-compatibility notes this
 * one shares (DOM.resolveNode, Target.attachToBrowserTarget).
 *
 *   node examples/capture-attr-purchase.mjs [--chrome /path/to/chrome]
 */
import { createServer } from "node:http";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startBridge, LocalVaultDriver, sealVault } from "../dist/index.js";
import { executeIntent } from "./intent-executor.mjs";
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

// A shop: signup, login, a payment-token page where the value sits in a
// data-clipboard-text attribute (not element text -- the "copy button"
// pattern the README calls out), and an order endpoint the token protects.
const users = new Map();
let issuedToken = "";
const orders = [];
const bodyOf = (req) => new Promise((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
const site = createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  const signedIn = (req.headers.cookie ?? "").includes("session=merchant1");
  if (u.pathname === "/signup" && req.method === "GET")
    return void res.end(`<!doctype html><body><form action="/signup" method="post"><input id="email" name="email"><input id="password" name="password" type="password"><button id="go" type="submit">Create shop account</button></form></body>`);
  if (u.pathname === "/signup" && req.method === "POST") {
    const p = new URLSearchParams(await bodyOf(req));
    users.set(p.get("email"), p.get("password") || "");
    return void res.writeHead(302, { location: "/welcome" }).end();
  }
  if (u.pathname === "/welcome") return void res.end("<!doctype html><h1 id=ok>Shop created</h1>");
  if (u.pathname === "/login" && req.method === "GET")
    return void res.end(`<!doctype html><body><form action="/session" method="post"><input id="u" name="username" value="shop@merchant1.example"><input id="p" name="password" type="password"></form></body>`);
  if (u.pathname === "/session" && req.method === "POST") {
    const p = new URLSearchParams(await bodyOf(req));
    if (users.get(p.get("username")) !== p.get("password")) return void res.writeHead(302, { location: "/login?bad=1" }).end();
    return void res.writeHead(302, { location: "/dashboard", "set-cookie": "session=merchant1; Path=/" }).end();
  }
  if (u.pathname === "/dashboard") return void res.writeHead(signedIn ? 200 : 401, { "content-type": "text/html" }).end(`<!doctype html><body><div id="who">${signedIn ? "shop@merchant1.example" : "anonymous"}</div></body>`);
  if (u.pathname === "/settings/payment-token") {
    if (!signedIn) return void res.writeHead(401).end("no");
    // The value is on a copy button's data attribute, not the button's own text.
    return void res.writeHead(200, { "content-type": "text/html" }).end(
      `<!doctype html><body><button id="generate">Generate token</button><button id="copy" data-clipboard-text="">Copy</button><script>
        document.getElementById('generate').addEventListener('click', async () => {
          const r = await fetch('/issue-token', { method: 'POST', credentials: 'include' });
          document.getElementById('copy').setAttribute('data-clipboard-text', (await r.json()).token);
        });
      </script></body>`);
  }
  if (u.pathname === "/issue-token" && req.method === "POST") {
    if (!signedIn) return void res.writeHead(401).end("no");
    issuedToken = "pt_live_" + Math.abs(Date.now() ^ (Math.random() * 1e9 | 0)).toString(36);
    return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ token: issuedToken }));
  }
  // The "purchase" endpoint the captured token protects.
  if (u.pathname === "/api/purchase" && req.method === "POST") {
    // The intent executor's fetch() sends no body -- both token (injected,
    // secret side) and sku (templated from params) arrive on the query string.
    if (u.searchParams.get("token") !== issuedToken) return void res.writeHead(401).end('{"error":"bad token"}');
    const sku = u.searchParams.get("sku");
    orders.push(sku);
    return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ orderId: orders.length, sku }));
  }
  res.writeHead(404).end();
});
await new Promise((r) => site.listen(0, "127.0.0.1", r));
const origin = `http://127.0.0.1:${site.address().port}`;

const dir = mkdtempSync(join(tmpdir(), "1claw-shop-"));
const vaultPath = join(dir, "vault.json");
writeFileSync(vaultPath, JSON.stringify(await sealVault({
  entries: [],
  registrations: [{ id: "shop", signupUrl: `${origin}/signup`, loginUrl: `${origin}/login`, username: "shop@merchant1.example",
    allowedHosts: ["127.0.0.1"], usernameSelector: "#email", passwordSelector: "#password", submitSelector: "#go",
    success: { urlChanges: true } }],
  captures: [{ id: "shop-token", captureUrl: `${origin}/settings/payment-token`, loginUrl: `${origin}/login`,
    allowedHosts: ["127.0.0.1"], generateSelector: "#generate", valueSelector: "#copy", valueAttr: "data-clipboard-text" }],
}, PASSPHRASE)));

const backend = new LocalVaultDriver({ path: vaultPath, passphrase: PASSPHRASE });
await backend.open();
const bridge = await startBridge({ executablePath: CHROME, backend, host: "127.0.0.1", port: 0, args: ["--headless=new"] });
let liveGeneration = 0;
const observe = (frameId) => () => ({ tabOrigin: origin, frameOrigin: origin, formActionOrigin: origin, frameId, generation: liveGeneration });

try {
  console.log(`\n=== TEST: shop site, real Puppeteer agent, attribute capture + purchase activity ===`);
  console.log(`  site: ${origin}`);

  const reg = await bridge.callTool("begin_credential_registration", { site_id: "shop" }, observe("shop"));
  console.log(`  1. register       -> ${JSON.stringify(reg)}`);

  const browser = await puppeteer.connect({ browserWSEndpoint: bridge.url });
  const page = await browser.newPage();
  await page.goto(`${origin}/dashboard`);
  liveGeneration++;
  const targetId = page.target()._targetId;
  console.log(`  2. before login   -> ${await page.evaluate(() => document.querySelector("#who").textContent)}`);

  const fill = await bridge.callTool("request_fill", { binding_id: "shop", target_id: targetId, selector: "#p" }, observe(targetId));
  console.log(`  3. login fill     -> ${JSON.stringify(fill)}`);
  await page.reload();
  liveGeneration++;
  console.log(`  4. after login    -> ${await page.evaluate(() => document.querySelector("#who").textContent)}`);

  const cap = await bridge.callTool("begin_credential_capture", { site_id: "shop-token", target_id: targetId }, observe(targetId));
  console.log(`  5. capture token  -> ${JSON.stringify(cap)} (from a data-attribute, not element text)`);

  // 6. The activity: a purchase using the captured token via the execution
  // intent stand-in, the way a real agent would trigger a paid action.
  const result = await executeIntent({
    vaultPath, passphrase: PASSPHRASE,
    binding: { method: "POST", url: `${origin}/api/purchase?token={{token}}&sku={{sku}}`, secretEntryId: "shop-token", inject: { as: "query", name: "token" } },
    params: { sku: "WIDGET-42" },
  });
  console.log(`  6. purchase       -> HTTP ${result.status}, body ${result.body}`);

  const leaked = [JSON.stringify(reg), JSON.stringify(fill), JSON.stringify(cap), JSON.stringify(result)]
    .some((s) => (issuedToken && s.includes(issuedToken)) || s.includes(users.get("shop@merchant1.example")));
  const ok = reg.status === "registered" && fill.status === "filled" && cap.status === "captured"
    && result.status === 200 && JSON.parse(result.body).sku === "WIDGET-42" && !leaked;
  console.log(`\n  agent ever saw the password or token: ${leaked ? "YES -- BUG" : "no"}`);
  console.log(`  ${ok ? "OK" : "FAILED"}\n`);
  await browser.disconnect();
  process.exitCode = ok ? 0 : 1;
} finally {
  await bridge.close();
  await new Promise((r) => site.close(r));
}
