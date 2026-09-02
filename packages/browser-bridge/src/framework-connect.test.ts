// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * Can a stock framework client actually drive the bridge?
 *
 * The README tells people to point their framework's `cdp_url` at the URL the
 * bridge prints. `handshake.test.ts` proves the proxy answers `Browser.getVersion`
 * the way those clients expect, but it uses a synthetic client — so it stays
 * green while a real Puppeteer or Playwright still cannot open a page. This is
 * the test that drives the real thing, connect -> newPage -> goto, so the claim
 * is checked against the clients people actually bring (Puppeteer, Playwright,
 * and by extension the Playwright-based agents browser-use and Stagehand).
 *
 * These arrived as `it.fails` — a live tripwire for a gap that was real when
 * they were written, and right on every detail. A stock client got past
 * `Browser.getVersion` and was refused on the next method it sent
 * (`Target.getBrowserContexts` for Puppeteer, `Browser.setDownloadBehavior` for
 * Playwright), and past those it still could not open a page. The tripwire has
 * fired, so the `.fails` is gone and these are ordinary tests.
 *
 * What it took, and why each part is worth keeping in view:
 *
 *   - the connect handshake answered locally rather than forwarded, so a client
 *     is satisfied without Chromium being put into global discovery;
 *   - auto-attach performed for real on the client's behalf, so the sessionId it
 *     is handed is one that works and is recorded as its own;
 *   - the two `Network.*ExtraInfo` events forwarded with their headers emptied.
 *     They were refused outright — they carry `Cookie` and `Set-Cookie` — and a
 *     client's network bookkeeping will not settle a navigation without them.
 *     `page.goto()` hung while `page.content()` returned the new document,
 *     because the navigation had in fact completed. Diffing the event stream
 *     against a raw Chromium showed those two as the only difference;
 *   - locally-answered replies echoing the `sessionId` they were sent on. A
 *     client routes a reply by its session, so one that arrives on the root
 *     session carrying an id the root never sent is a protocol violation.
 *     Playwright asserts on it; Puppeteer does not — which is exactly why one
 *     client is not enough to check this with.
 *
 * `puppeteer-core` and `playwright-core` are devDependencies, so CI runs this.
 *
 * They arrived optional, to keep Playwright's install out of everyone's CI —
 * a fair concern about `playwright`, which downloads browsers. `playwright-core`
 * and `puppeteer-core` are the libraries alone: 21MB together and no browser
 * download, because they drive a Chromium you already have. Left optional, the
 * one test that checks the README's headline claim would skip in CI, and a
 * skipped test is indistinguishable from a passing one.
 *
 * The optional import stays, so a checkout without them still runs the rest of
 * the suite. Point at a Chromium with ONECLAW_BRIDGE_CHROME if it is not at the
 * default path.
 */
import { existsSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startBridge, type BridgeHandle } from "./bridge.js";
import { MockVaultDriver } from "./drivers/mock.js";

const CHROME =
  process.env.ONECLAW_BRIDGE_CHROME ??
  {
    darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    linux: "/usr/bin/google-chrome",
  }[process.platform as "darwin" | "linux"] ??
  "";
const HAVE_CHROME = CHROME !== "" && existsSync(CHROME);
const LAUNCH_ARGS = [
  "--headless=new",
  ...(process.env.CI && process.platform === "linux"
    ? ["--no-sandbox", "--disable-dev-shm-usage"]
    : []),
];

/**
 * Import an optional peer by a name the type checker cannot resolve, so a
 * missing framework is a skipped test rather than a broken build.
 */
async function optional(name: string): Promise<any | null> {
  try {
    return await import(/* @vite-ignore */ name);
  } catch {
    return null;
  }
}

const puppeteer = await optional("puppeteer-core");
const playwright = await optional("playwright-core");

let server: Server;
let origin = "";

beforeAll(async () => {
  server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<!doctype html><title>ok</title><body><h1>ok</h1></body>");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

async function bridge(): Promise<BridgeHandle> {
  const backend = new MockVaultDriver({
    bindings: [{ id: "x", secret: "p", loginUrl: origin, allowedHosts: ["127.0.0.1"] }],
  });
  return startBridge({ executablePath: CHROME, backend, host: "127.0.0.1", port: 0, args: LAUNCH_ARGS });
}

const runPuppeteer = HAVE_CHROME && puppeteer ? it : it.skip;
const runPlaywright = HAVE_CHROME && playwright ? it : it.skip;

describe("a stock framework client can drive the bridge", () => {
  runPuppeteer(
    "puppeteer-core connects, opens a page, and navigates",
    async () => {
      const b = await bridge();
      try {
        const browser = await puppeteer.connect({ browserWSEndpoint: b.url });
        const page = await browser.newPage();
        await page.goto(origin);
        expect(await page.title()).toBe("ok");
        await browser.disconnect();
      } finally {
        await b.close();
      }
    },
    40_000,
  );

  runPlaywright(
    "playwright-core connects, opens a page, and navigates",
    async () => {
      const b = await bridge();
      try {
        const browser = await playwright.chromium.connectOverCDP(b.url);
        const ctx = browser.contexts()[0] ?? (await browser.newContext());
        const page = await ctx.newPage();
        await page.goto(origin);
        expect(await page.title()).toBe("ok");
        await browser.close();
      } finally {
        await b.close();
      }
    },
    40_000,
  );
});
