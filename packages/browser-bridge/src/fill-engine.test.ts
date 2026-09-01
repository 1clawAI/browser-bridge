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
