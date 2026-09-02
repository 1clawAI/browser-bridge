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
 * These are `it.fails` on purpose. As of the handshake answerer landing
 * (issue #2), a stock client gets past `Browser.getVersion` and then blocks:
 * with the gate enforced it is refused on the next method it sends
 * (`Target.getBrowserContexts` for Puppeteer, `Browser.setDownloadBehavior` for
 * Playwright); even with every method allowed, `newPage()` never resolves,
 * because the proxy does not synthesise the target-lifecycle events
 * (`targetCreated` / `attachedToTarget` / `targetInfoChanged`) the client waits
 * for to build its Page. The body below is the real acceptance test; when the
 * answerer presents a coherent target lifecycle for a client's own pages, this
 * starts passing, `it.fails` turns it red, and that is the signal to drop the
 * `.fails`.
 *
 * The framework clients are NOT dependencies of this package — a smoke test
 * should not pull Playwright's install into everyone's CI. The test skips
 * unless they are present, so to run it locally:
 *
 *   pnpm add -D -w puppeteer-core playwright-core
 *   pnpm test framework-connect
 *
 * and point at a Chromium with ONECLAW_BRIDGE_CHROME if it is not at the
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

const runPuppeteer = HAVE_CHROME && puppeteer ? it.fails : it.skip;
const runPlaywright = HAVE_CHROME && playwright ? it.fails : it.skip;

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
