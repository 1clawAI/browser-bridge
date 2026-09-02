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
    authorizeFill: async () => ({ ...GRANT }) as never,
    consumeFill: async () => SecretHandle.fromUtf8(PASSWORD),
    audit: async (e: unknown) => void audits.push(e),
    policySnapshot: async () => ({}) as never,
  } as unknown as VaultBackend;
}

const FILL_ARGS = { binding_id: "b1", target_id: TARGET, selector: "#password" } as const;

/** What the bridge reads off the live page. Never what the agent claims. */
const observed = (over: Partial<ReturnType<typeof base>> = {}) => () => ({ ...base(), ...over });
const base = () => ({
  tabOrigin: "https://app.example.com",
  frameOrigin: "https://app.example.com",
  formActionOrigin: "https://app.example.com",
  frameId: TARGET,
  generation: 0,
});

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
    // The tool's registered name. Calling anything else takes the "unknown tool"
    // path, which returns an error containing no secret and asserts nothing —
    // this test used to call "browser_fill" and pass without typing a character.
    expect(b.tools.map((t) => t.name)).toContain("request_fill");

    const result = await b.callTool("request_fill", FILL_ARGS, observed());

    // Whatever the outcome, the secret must not be in it.
    expect(JSON.stringify(result)).not.toContain(PASSWORD);

    // Unconditional: a guard around these is a guard around the only assertions
    // that say the fill happened at all.
    const typed = transport.sent.filter((m: CdpMessage) => m.method === "Input.insertText");
    expect(typed.length).toBeGreaterThan(0);
    // It went into a target the agent never scripted, addressed by session.
    expect(transport.sent.some((m) => m.method === "Target.createTarget")).toBe(true);
    expect(typed[0]?.sessionId).toBeDefined();
    expect(typed[0]?.params?.targetId).toBeUndefined();
  });

  it("bumps the generation from the browser's own navigation events", async () => {
    // The TOCTOU check is only as good as its clock. If the generation came
    // from anything the agent said, the agent could hold it still while moving
    // the page underneath the fill.
    const { bridge: b, transport } = await start();

    // A navigation the *agent* never mentioned. The fill still has to notice.
    transport.emit({ method: "Page.frameNavigated", params: { frame: { id: TARGET } } });

    const result = await b.callTool("request_fill", FILL_ARGS, observed());
    // Its own status, not an error: an agent that retries an error is asking
    // for the credential to land on whatever page arrived in the meantime.
    expect(result.status).toBe("aborted");
    expect(result).toMatchObject({ reason: "generation_stale" });
    expect(JSON.stringify(result)).not.toContain(PASSWORD);
    // Nothing was typed into the page that moved.
    expect(transport.sent.filter((m) => m.method === "Input.insertText")).toHaveLength(0);
  });

  it("opens a session on the backend and uses the id it returns", async () => {
    // The core used to invent `randomBytes(12)` as a session id and never call
    // openSession at all. Every driver implemented it; nothing called it. The
    // saas driver therefore never held a session token and consumeFill threw,
    // and the mock refused every fill as session_expired — the entire client
    // path was broken for both backends, hidden because the end-to-end tests
    // drove the vault's HTTP API instead of going through the bridge.
    const opened: string[] = [];
    const closed: string[] = [];
    const back = backend() as unknown as Record<string, unknown>;
    back.openSession = async (ctx: { clientId: string }) => {
      opened.push(ctx.clientId);
      return { id: "session-from-backend", createdAt: "", expiresAt: "" };
    };
    back.closeSession = async (id: string) => void closed.push(id);
    let seen = "";
    back.authorizeFill = async (r: { sessionId: string }) => {
      seen = r.sessionId;
      return { ...GRANT };
    };

    bridge = await startBridge({
      executablePath: "/nonexistent",
      host: "127.0.0.1",
      port: 0,
      transport: new FakeCdpTransport(),
      backend: back as never,
    });
    expect(opened).toHaveLength(1);

    await bridge.callTool("request_fill", FILL_ARGS, observed());
    // The id the backend issued, not one the core made up.
    expect(seen).toBe("session-from-backend");

    await bridge.close();
    bridge = undefined;
    // And the backend is told, rather than left to time the session out.
    expect(closed).toEqual(["session-from-backend"]);
  });

  it("closes the transport when the bridge closes", async () => {
    const transport = new FakeCdpTransport();
    const { bridge: b } = await start(transport);
    await b.close();
    bridge = undefined;
    expect(transport.closed).toBe(true);
  });
});
