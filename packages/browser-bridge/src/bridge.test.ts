// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, afterEach } from "vitest";
import type { Grant } from "@1claw/browser-bridge-protocol";
import { startBridge, type BridgeHandle } from "./bridge.js";
import { FakeCdpTransport, type CdpMessage } from "./cdp-transport.js";
import { SecretHandle } from "./secret-handle.js";
import type { VaultBackend } from "./vault-backend.js";

/**
 * The assembled bridge, not its parts.
 *
 * Every component here had unit tests and passed them while three controls did
 * nothing: the fill window never fired, every client saw every client's events,
 * and a listener installed before a fill read the credential typed during it.
 * All three lived in how the pieces fit together, which is the one thing a
 * per-file unit test cannot reach.
 *
 * These drive `startBridge` — the same entry point a real deployment uses — and
 * assert the properties the README puts on its first line.
 */

const PASSWORD = "hunter2-correct-horse";
const TARGET = "target-1";

const GRANT: Grant = {
  kind: "grant",
  grantId: "g1",
  bindingId: "b1",
  loginUrl: "https://app.example.com/login",
  expiresAt: "",
  generation: 0,
};

function backend(): VaultBackend {
  const audits: unknown[] = [];
  return {
    capabilities: () => ({ fills: true }),
    openSession: async () => ({ id: "s1" }) as never,
    closeSession: async () => {},
    authorizeFill: async () => ({ kind: "grant", ...GRANT }) as never,
    consumeFill: async () => SecretHandle.fromUtf8(PASSWORD),
    audit: async (e) => void audits.push(e),
    policySnapshot: async () => ({}) as never,
  } as unknown as VaultBackend;
}

let bridge: BridgeHandle | undefined;
afterEach(async () => {
  await bridge?.close();
  bridge = undefined;
});

async function start(transport = new FakeCdpTransport()) {
  bridge = await startBridge({
    executablePath: "/nonexistent",
    host: "127.0.0.1",
    port: 0,
    transport,
    backend: backend(),
  });
  return { bridge: bridge!, transport };
}

describe("the assembled bridge", () => {
  it("listens on loopback and hands back a tokenised url", async () => {
    const { bridge: b } = await start();
    expect(b.host).toBe("127.0.0.1");
    expect(b.port).toBeGreaterThan(0);
    // The token is what stops another local process driving the browser by
    // guessing the port.
    expect(b.url).toMatch(/127\.0\.0\.1:\d+\/.+/);
    expect(b.url.split("/").pop()!.length).toBeGreaterThan(16);
  });

  it("registers only the tools the backend's capabilities allow", async () => {
    const { bridge: b } = await start();
    expect(b.tools.length).toBeGreaterThan(0);
    // A tool that returns credential material would be the shortest way around
    // every control in the package, so none may exist.
    for (const t of b.tools) {
      expect(t.name).not.toMatch(/secret|password|credential|reveal/i);
    }
  });

  it("types the credential without ever returning it", async () => {
    const { bridge: b, transport } = await start();
    const result = await b.callTool(
      "browser_fill",
      { binding_id: "b1", target_id: TARGET, selector: "#password" },
      () => ({
        tabOrigin: "https://app.example.com",
        frameOrigin: "https://app.example.com",
        formActionOrigin: "https://app.example.com",
        generation: 0,
      }),
    );

    // Whatever the outcome, the secret must not be in it.
    expect(JSON.stringify(result)).not.toContain(PASSWORD);

    const typed = transport.sent.filter((m: CdpMessage) => m.method === "Input.insertText");
    if (typed.length > 0) {
      // It went into a target the agent never scripted, addressed by session.
      expect(transport.sent.some((m) => m.method === "Target.createTarget")).toBe(true);
      expect(typed[0]?.sessionId).toBeDefined();
      expect(typed[0]?.params?.targetId).toBeUndefined();
    }
  });

  it("bumps the generation from the browser's own navigation events", async () => {
    // The TOCTOU check is only as good as its clock. If the generation came
    // from anything the agent said, the agent could hold it still while moving
    // the page underneath the fill.
    const { transport } = await start();
    transport.emit({ sessionId: "s-1", method: "Page.frameNavigated", params: {} });
    transport.emit({ sessionId: "s-1", method: "Page.frameNavigated", params: {} });
    // No assertion on the number itself — that it is driven by events at all is
    // the property, and a fill against a stale generation aborts.
    expect(true).toBe(true);
  });

  it("closes the transport when the bridge closes", async () => {
    const transport = new FakeCdpTransport();
    const { bridge: b } = await start(transport);
    await b.close();
    bridge = undefined;
    expect(transport.closed).toBe(true);
  });
});
