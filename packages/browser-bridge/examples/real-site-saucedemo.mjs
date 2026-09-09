#!/usr/bin/env node
// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * A real, live third-party site over the real internet, not a local fixture:
 * saucedemo.com, the widely-used QA-industry-standard practice storefront.
 * Driven by a stock `puppeteer-core` client, with a genuine activity
 * afterward (add to cart), not just a login check.
 *
 * This depends on an external site staying up and keeping its current form
 * markup -- unlike the other examples, which are all self-contained local
 * fixtures. Expect this one specifically to need attention if saucedemo.com
 * ever changes.
 *
 * It also demonstrates something worth knowing if you integrate against a
 * real single-page app: saucedemo.com is a React app that keeps mutating
 * history (router setup, `history.replaceState`) for a moment *after* its
 * initial load event fires. Snapshotting the live generation once, right
 * after `page.goto()` resolves, and using that as `current_generation` in a
 * fill request is a race -- confirmed by instrumenting the bridge directly,
 * a `Page.navigatedWithinDocument` landed in exactly that window and aborted
 * the fill with `{"status":"aborted","reason":"navigated"}`. The fix here is
 * to track real navigation events and wait for them to go quiet before
 * requesting the fill, not to guess a fixed count -- a static site's
 * generation is stable the instant it loads, a live SPA's is not.
 *
 *   node examples/real-site-saucedemo.mjs [--chrome /path/to/chrome]
 */
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startBridge, LocalVaultDriver, sealVault } from "../dist/index.js";
import puppeteer from "puppeteer-core";

const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf(`--${n}`); return i > -1 ? argv[i + 1] : undefined; };
const CHROME =
  flag("chrome") ?? process.env.ONECLAW_BRIDGE_CHROME ??
  { darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    linux: "/usr/bin/google-chrome" }[process.platform];
if (!CHROME || !existsSync(CHROME)) { console.error(`No Chromium at ${CHROME ?? "(unknown)"}.`); process.exit(2); }
const PASSPHRASE = "a-long-enough-demo-passphrase";
const ORIGIN = "https://www.saucedemo.com";

const dir = mkdtempSync(join(tmpdir(), "1claw-sauce-"));
const vaultPath = join(dir, "vault.json");
writeFileSync(vaultPath, JSON.stringify(await sealVault({
  entries: [{ id: "saucedemo", secret: "secret_sauce",
    loginUrl: `${ORIGIN}/`, allowedHosts: ["www.saucedemo.com"],
    username: "standard_user", usernameSelector: "#user-name",
    passwordSelector: "#password", submitSelector: "#login-button" }],
}, PASSPHRASE)));

const backend = new LocalVaultDriver({ path: vaultPath, passphrase: PASSPHRASE });
await backend.open();
const bridge = await startBridge({ executablePath: CHROME, backend, host: "127.0.0.1", port: 0, args: ["--headless=new"] });
let liveGeneration = 0;
const observe = (frameId) => () => ({ tabOrigin: ORIGIN, frameOrigin: ORIGIN, formActionOrigin: ORIGIN, frameId, generation: liveGeneration });

try {
  console.log(`\n=== TEST: real live site #2 (${ORIGIN}), Puppeteer, add-to-cart activity ===`);
  const browser = await puppeteer.connect({ browserWSEndpoint: bridge.url });
  const page = await browser.newPage();
  // Track real navigations on the main frame, the same event the bridge
  // itself bumps its live generation counter on (Page.frameNavigated /
  // Page.navigatedWithinDocument). A React SPA like this one can fire more
  // of these on initial load than a plain server-rendered page (client-side
  // route setup, history.replaceState, etc.), so guessing a fixed count per
  // site is fragile -- count for real instead.
  page.on("framenavigated", (frame) => { if (frame === page.mainFrame()) liveGeneration++; });
  await page.goto(ORIGIN);
  const targetId = page.target()._targetId;
  const t0 = Date.now();

  // A React app like this one keeps mutating history (router setup,
  // history.replaceState) for a moment after the initial load event fires --
  // confirmed by instrumenting the bridge directly: a Page.navigatedWithinDocument
  // landed between this script's snapshot and the fill's own re-check, bumping
  // the live generation out from under an authorization taken too early. Real
  // fix: wait for navigation activity to go quiet before asking for the fill,
  // not guess a fixed event count for a site whose own JS is still moving.
  let lastCount = -1, settleChecks = 0;
  while (settleChecks < 10) {
    if (liveGeneration === lastCount) { settleChecks++; } else { settleChecks = 0; lastCount = liveGeneration; }
    await new Promise((r) => setTimeout(r, 150));
  }
  console.log(`  1. loaded homepage, settled at generation=${liveGeneration}`);

  const fill = await bridge.callTool("request_fill",
    { binding_id: "saucedemo", target_id: targetId, selector: "#password" }, observe(targetId));
  console.log(`  2. fill -> ${JSON.stringify(fill)} (${Date.now() - t0}ms)`);

  await page.goto(`${ORIGIN}/inventory.html`);
  const products = await page.evaluate(() => document.querySelector(".title")?.textContent ?? "");
  console.log(`  3. after fill, on inventory page -> "${products}"`);

  // 4. The activity: add an item to cart, driven by Puppeteer, on the agent's
  // own authenticated tab.
  await page.evaluate(() => document.querySelector("#add-to-cart-sauce-labs-backpack")?.click());
  await page.waitForFunction(() => document.querySelector(".shopping_cart_badge")?.textContent === "1");
  const cartCount = await page.evaluate(() => document.querySelector(".shopping_cart_badge")?.textContent);
  console.log(`  4. added item to cart -> cart badge shows "${cartCount}"`);

  const leaked = JSON.stringify(fill).includes("secret_sauce");
  const ok = fill.status === "filled" && products === "Products" && cartCount === "1" && !leaked;
  console.log(`\n  agent ever saw the password: ${leaked ? "YES -- BUG" : "no"}`);
  console.log(`  ${ok ? "OK" : "FAILED"}: real e-commerce site, real login, real add-to-cart, no password leaked\n`);
  await browser.disconnect();
  process.exitCode = ok ? 0 : 1;
} finally {
  await bridge.close();
}
