// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { existsSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import WebSocket from "ws";
import { startBridge } from "./bridge.js";
import { MockVaultDriver } from "./drivers/mock.js";
import { PipeCdpTransport } from "./pipe-transport.js";

/**
 * Against a real Chromium, over a real pipe.
 *
 * Everything else in this suite runs on FakeCdpTransport, which answers the
 * protocol we believe Chromium speaks. That belief has been wrong before: the
 * fill window was matched on `params.targetId` for months, a dialect Chromium
 * does not use for the methods that read a form field, and every test passed
 * because the fake answered the same dialect. A double that agrees with the
 * code cannot catch the code disagreeing with the browser.
 *
 * Skipped when Chromium is absent, so a machine without it does not fail the
 * suite — but skipping is reported, because a test that quietly does not run
 * is indistinguishable from one that passes.
 */
const CHROME =
  process.env.ONECLAW_BRIDGE_CHROME ??
  {
    darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    linux: "/usr/bin/google-chrome",
  }[process.platform as "darwin" | "linux"] ??
  "";

const HAVE_CHROME = CHROME !== "" && existsSync(CHROME);
const PASSWORD = "hunter2-real-chromium";

/**
 * Flags this test adds on top of the transport's own.
 *
 * `--headless=new` because a CI runner has no display, and the transport does
 * not choose headlessness for callers — a bridge on someone's laptop wants a
 * visible window.
 *
 * `--no-sandbox` on Linux CI only. GitHub's ubuntu runners ship
 * /usr/bin/google-chrome, so the existsSync check above passes, and then Chrome
 * exits 1 with ECONNRESET because it cannot set up its sandbox as root without
 * user namespaces. That failure is about the runner, not about this package —
 * but the flag genuinely weakens the browser, so it is scoped to CI rather than
 * applied everywhere and forgotten.
 */
const LAUNCH_ARGS: string[] = [
  "--headless=new",
  ...(process.env.CI && process.platform === "linux"
    ? ["--no-sandbox", "--disable-dev-shm-usage"]
    : []),
];

let server: Server;
let origin = "";

beforeAll(async () => {
  // A real login form, served over a real socket. `about:blank` would not
  // exercise DOM.querySelector or Input.insertText against actual layout.
  server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<!doctype html><html><body>
      <form action="/submit" method="post">
        <input id="username" name="username" type="text">
        <input id="password" name="password" type="password">
      </form>
    </body></html>`);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

describe.skipIf(!HAVE_CHROME)("against a real Chromium", () => {
  it("completes the attach handshake Chromium actually implements", async () => {
    const t = PipeCdpTransport.launch({ executablePath: CHROME, args: LAUNCH_ARGS });
    try {
      const target = (await t.send({
        method: "Target.createTarget",
        params: { url: "about:blank" },
      })) as { result?: { targetId?: string } };
      const targetId = target.result?.targetId;
      expect(typeof targetId).toBe("string");

      // The handshake the fake was written to imitate. If Chromium answered
      // differently, every fill would address a session that does not exist.
      const attached = (await t.send({
        method: "Target.attachToTarget",
        params: { targetId, flatten: true },
      })) as { result?: { sessionId?: string } };
      expect(typeof attached.result?.sessionId).toBe("string");
      // And a session id is not a target id — the two were conflated once.
      expect(attached.result?.sessionId).not.toBe(targetId);
    } finally {
      await t.close();
    }
  }, 60_000);

  it("types a credential into a real form field, addressed by session", async () => {
    const t = PipeCdpTransport.launch({ executablePath: CHROME, args: LAUNCH_ARGS });
    try {
      const target = (await t.send({
        method: "Target.createTarget",
        params: { url: "about:blank" },
      })) as { result?: { targetId?: string } };
      const targetId = target.result!.targetId!;
      const attached = (await t.send({
        method: "Target.attachToTarget",
        params: { targetId, flatten: true },
      })) as { result?: { sessionId?: string } };
      const sessionId = attached.result!.sessionId!;

      await t.send({ sessionId, method: "Page.enable" });
      await t.send({ sessionId, method: "Runtime.enable" });
      await t.send({ sessionId, method: "Page.navigate", params: { url: origin } });

      // Wait for the form rather than sleeping a fixed interval.
      let ready = false;
      for (let i = 0; i < 60 && !ready; i++) {
        const probe = (await t.send({
          sessionId,
          method: "Runtime.evaluate",
          params: { expression: "!!document.querySelector('#password')", returnByValue: true },
        })) as { result?: { result?: { value?: boolean } } };
        ready = probe.result?.result?.value === true;
        if (!ready) await new Promise((r) => setTimeout(r, 100));
      }
      expect(ready, "the form never appeared").toBe(true);

      await t.send({
        sessionId,
        method: "Runtime.evaluate",
        params: { expression: "document.querySelector('#password').focus()" },
      });
      // The method the fill engine uses. Session-addressed, no targetId.
      await t.send({ sessionId, method: "Input.insertText", params: { text: PASSWORD } });

      const read = (await t.send({
        sessionId,
        method: "Runtime.evaluate",
        params: { expression: "document.querySelector('#password').value", returnByValue: true },
      })) as { result?: { result?: { value?: string } } };

      // The whole point: the credential reached the field in a real browser.
      expect(read.result?.result?.value).toBe(PASSWORD);
    } finally {
      await t.close();
    }
  }, 90_000);

  it("keeps a second browser context from seeing the first's page", async () => {
    // The per-client BrowserContext isolation the package promises. A shared
    // context would let one agent read another's targets — the shape of the
    // event-broadcast bug found in August.
    const t = PipeCdpTransport.launch({ executablePath: CHROME, args: LAUNCH_ARGS });
    try {
      const ctxA = (await t.send({ method: "Target.createBrowserContext" })) as {
        result?: { browserContextId?: string };
      };
      const ctxB = (await t.send({ method: "Target.createBrowserContext" })) as {
        result?: { browserContextId?: string };
      };
      const a = ctxA.result?.browserContextId;
      const b = ctxB.result?.browserContextId;
      expect(typeof a).toBe("string");
      expect(a).not.toBe(b);

      const made = (await t.send({
        method: "Target.createTarget",
        params: { url: origin, browserContextId: a },
      })) as { result?: { targetId?: string } };
      const targetId = made.result!.targetId!;

      const targets = (await t.send({ method: "Target.getTargets" })) as {
        result?: { targetInfos?: { targetId: string; browserContextId?: string }[] };
      };
      const info = targets.result?.targetInfos?.find((x) => x.targetId === targetId);
      // Chromium reports the owning context, which is what the proxy scopes on.
      expect(info?.browserContextId).toBe(a);
      expect(info?.browserContextId).not.toBe(b);
    } finally {
      await t.close();
    }
  }, 60_000);
});

describe.skipIf(HAVE_CHROME)("against a real Chromium", () => {
  it("is skipped because no Chromium was found", () => {
    // Visible rather than silent: set ONECLAW_BRIDGE_CHROME to run it.
    expect(HAVE_CHROME).toBe(false);
  });
});

describe("launch flags given to startBridge", () => {
  /**
   * That the composition root forwards them at all.
   *
   * `BridgeOptions` did not have an `args` field. Three test files passed one
   * anyway and it was dropped on the floor: silently on a desktop, where a
   * visible window is fine, and fatally on a CI runner with no display, where
   * Chromium exits 1. Nothing caught it, because the tests are not typechecked
   * and no test asserted the forwarding.
   *
   * Typechecking the tests — now gated in CI — catches an option that does not
   * exist. It cannot catch one that exists and is never passed on, which is the
   * same failure with a nicer type signature. So this asserts the effect: ask
   * for headless, and the browser that comes back has to be a headless one.
   */
  it.skipIf(!HAVE_CHROME)("reach Chromium, so --headless=new produces a headless browser", async () => {
    const bridge = await startBridge({
      executablePath: CHROME,
      backend: new MockVaultDriver({ bindings: [] }),
      host: "127.0.0.1",
      port: 0,
      args: LAUNCH_ARGS,
    });
    // Asked over the gate, as a framework would — the transport is not public,
    // and handing a client the raw pipe is the one thing this package will not
    // do. Browser.getVersion is allowlisted precisely so clients can attach.
    const ws = new WebSocket(bridge.url);
    try {
      await new Promise((res, rej) => {
        ws.once("open", res);
        ws.once("error", rej);
      });
      const reply = await new Promise<{ result?: { userAgent?: string } }>((resolve) => {
        ws.once("message", (d) => resolve(JSON.parse(String(d))));
        ws.send(JSON.stringify({ id: 1, method: "Browser.getVersion" }));
      });
      const ua = String(reply.result?.userAgent ?? "");
      expect(ua, "not headless — the flag never reached the browser").toContain("Headless");
    } finally {
      ws.close();
      await bridge.close();
    }
  }, 30_000);
});
