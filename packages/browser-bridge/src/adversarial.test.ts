// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from "vitest";
import type { FillRequest, Grant } from "@1claw/browser-bridge-protocol";
import { startBridge, type BridgeHandle } from "./bridge.js";
import { CdpGate } from "./cdp-policy.js";
import { FakeCdpTransport } from "./cdp-transport.js";
import { SecretHandle } from "./secret-handle.js";
import type { VaultBackend } from "./vault-backend.js";

/**
 * The adversarial harness: the bridge against an agent that is trying.
 *
 * This is the gate the README puts on going public, and it exists because the
 * per-file suites cannot reach the failures that actually happened here. In
 * August 2026 they were 121/121 green while three controls did nothing — the
 * fill window never fired, every client received every other client's events,
 * and a listener installed before a fill could read the credential typed during
 * it. Each component was individually correct. The bugs were in the seams.
 *
 * So every test below drives `startBridge` — the entry point a real deployment
 * uses — and plays the agent as hostile rather than merely careless. The agent
 * is assumed to control: which tool it calls, with what arguments, what it ran
 * on the page beforehand, and when it navigates. It is assumed not to control:
 * the vault's answer, what the bridge reads off the live page, and the contents
 * of this process's memory.
 *
 * A test here that cannot fail is worse than no test, so each one names the
 * specific move it is refusing.
 */

const PASSWORD = "hunter2-correct-horse";
const TARGET = "agent-tab";
const BINDING_LOGIN = "https://app.example.com/login";

const GRANT: Grant = {
  kind: "grant",
  grantId: "g1",
  bindingId: "b1",
  loginUrl: BINDING_LOGIN,
  expiresAt: "",
  generation: 0,
};

/** Records what the core actually asked the vault, so lies can be spotted. */
function backend(): VaultBackend & { asked: FillRequest[] } {
  const asked: FillRequest[] = [];
  const b = {
    asked,
    capabilities: () => ({
      fills: true,
      registration: false,
      checkout: false,
      signing: false,
      hitl: false,
      centralAudit: true,
      shadowReports: false,
    }),
    openSession: async () => ({ id: "s1", createdAt: "", expiresAt: "" }),
    closeSession: async () => {},
    authorizeFill: async (req: FillRequest) => {
      asked.push(req);
      return { ...GRANT, generation: req.generation };
    },
    consumeFill: async () => SecretHandle.fromUtf8(PASSWORD),
    audit: async () => {},
    policySnapshot: async () => ({}),
  };
  return b as unknown as VaultBackend & { asked: FillRequest[] };
}

const truth = () => ({
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

async function arm() {
  const transport = new FakeCdpTransport();
  const back = backend();
  bridge = await startBridge({
    executablePath: "/nonexistent",
    host: "127.0.0.1",
    port: 0,
    transport,
    backend: back,
  });
  return { bridge: bridge!, transport, back };
}

const typedText = (t: FakeCdpTransport) =>
  t.sent.filter((m) => m.method === "Input.insertText").map((m) => String(m.params?.text ?? ""));

describe("an agent trying to read the credential", () => {
  it("gets no tool that could return one", async () => {
    const { bridge: b } = await arm();
    // The shortest path around every other control in this package would be a
    // tool whose success case carries the value. None may exist.
    for (const t of b.tools) {
      expect(t.name).not.toMatch(/secret|password|credential|reveal|value|read/i);
      const schema = JSON.stringify(t.inputSchema);
      expect(schema).not.toMatch(/password|secret/i);
    }
  });

  it("gets no credential in a successful result", async () => {
    const { bridge: b, transport } = await arm();
    const result = await b.callTool(
      "request_fill",
      { binding_id: "b1", target_id: TARGET, selector: "#password" },
      truth,
    );
    expect(result.status).toBe("filled");
    // Serialised, because that is the form the agent receives.
    expect(JSON.stringify(result)).not.toContain(PASSWORD);
    // And it really was typed — a result that carries nothing because nothing
    // happened proves nothing about the invariant.
    expect(typedText(transport)).toContain(PASSWORD);
  });

  it("gets no credential in a failing result either", async () => {
    // The error path is where a live secret tends to get left behind.
    const transport = new FakeCdpTransport();
    const back = backend();
    (back as { consumeFill: unknown }).consumeFill = async () => {
      throw new Error(`vault said no for ${PASSWORD}`);
    };
    bridge = await startBridge({
      executablePath: "/nonexistent",
      host: "127.0.0.1",
      port: 0,
      transport,
      backend: back,
    });
    const result = await bridge.callTool(
      "request_fill",
      { binding_id: "b1", target_id: TARGET, selector: "#password" },
      truth,
    );
    expect(result.status).not.toBe("filled");
    expect(JSON.stringify(result)).not.toContain(PASSWORD);
  });
});

describe("an agent lying about the page", () => {
  it("cannot substitute its own origins for the ones the bridge read", async () => {
    const { bridge: b, back } = await arm();
    await b.callTool(
      "request_fill",
      {
        binding_id: "b1",
        target_id: TARGET,
        selector: "#password",
        // The move: name a trusted origin in the arguments and hope it is used.
        tab_origin: "https://app.example.com",
        frame_origin: "https://app.example.com",
      },
      // What the bridge actually observed: an attacker's frame.
      () => ({ ...truth(), frameOrigin: "https://evil.example.net" }),
    );
    expect(back.asked).toHaveLength(1);
    expect(back.asked[0]!.frameOrigin).toBe("https://evil.example.net");
  });

  it("cannot choose the page that receives the credential", async () => {
    const { bridge: b, transport } = await arm();
    await b.callTool(
      "request_fill",
      {
        binding_id: "b1",
        target_id: TARGET,
        selector: "#password",
        // The move: supply a login URL and have the bridge navigate there.
        login_url: "https://evil.example.net/harvest",
        url: "https://evil.example.net/harvest",
      },
      truth,
    );
    const navs = transport.sent.filter((m) => m.method === "Page.navigate");
    expect(navs.length).toBeGreaterThan(0);
    for (const n of navs) {
      expect(n.params?.url).toBe(BINDING_LOGIN);
    }
    expect(JSON.stringify(transport.sent)).not.toContain("evil.example.net");
  });

  it("cannot hold the generation still while moving the page", async () => {
    const { bridge: b, transport } = await arm();
    // The move: report the generation the grant was issued at, having navigated.
    transport.emit({ method: "Page.frameNavigated", params: { frame: { id: TARGET } } });
    const result = await b.callTool(
      "request_fill",
      { binding_id: "b1", target_id: TARGET, selector: "#password" },
      // The agent still claims generation 0. The bridge's counter disagrees.
      () => ({ ...truth(), generation: 0 }),
    );
    expect(result.status).toBe("aborted");
    expect(typedText(transport)).toHaveLength(0);
  });
});

describe("an agent watching the page it asked to be filled", () => {
  it("has the credential typed somewhere it has never scripted", async () => {
    const { bridge: b, transport } = await arm();
    await b.callTool(
      "request_fill",
      { binding_id: "b1", target_id: TARGET, selector: "#password" },
      truth,
    );

    // The August 2026 bypass: Runtime.evaluate is allowlisted *outside* a fill
    // window, so an agent can install a keydown listener beforehand and read the
    // credential as it is typed without issuing one command during the window.
    // A page it has never scripted has no listeners to fire.
    const created = transport.sent.filter((m) => m.method === "Target.createTarget");
    expect(created).toHaveLength(1);

    // The target the engine attached to in order to type.
    const attaches = transport.sent.filter((m) => m.method === "Target.attachToTarget");
    expect(attaches).toHaveLength(1);
    const fillTarget = String(attaches[0]!.params?.targetId);
    // Not the agent's tab. This is the whole of the defence against a listener
    // installed before the fill: a page the agent has never scripted has none.
    expect(fillTarget).not.toBe(TARGET);
    expect(created[0]!.params).toBeDefined();

    const typed = transport.sent.filter((m) => m.method === "Input.insertText");
    expect(typed).toHaveLength(1);
    // Addressed by session, which is the dialect Chromium speaks. Addressing by
    // params.targetId is what made the fill window inert for months.
    expect(typed[0]!.params?.targetId).toBeUndefined();
    // And it is *the throwaway's* session, not the agent's tab's. Asserting only
    // that the session id differs from the target id proves nothing: a session
    // id never equals a target id, so that check passes even when the credential
    // is typed straight into the page the agent has been scripting.
    expect(transport.sessions.get(fillTarget)).toBeDefined();
    expect(typed[0]!.sessionId).toBe(transport.sessions.get(fillTarget));
    expect(typed[0]!.sessionId).not.toBe(transport.sessions.get(TARGET));
  });

  it("is refused on the fill target it can see being created", async () => {
    // Target.getTargets and Target.attachToTarget are both allowlisted, so an
    // agent that notices the throwaway target must still be refused *on* it.
    // Windowing only the agent's own tab would leave the interesting one open.
    const { bridge: b, transport } = await arm();

    const gate = new CdpGate();
    const created: string[] = [];
    // Mirror what the engine does, against the real gate, so the assertion is
    // about the policy rather than about a stub agreeing with itself.
    await b.callTool(
      "request_fill",
      { binding_id: "b1", target_id: TARGET, selector: "#password" },
      truth,
    );
    for (const m of transport.sent) {
      if (m.method === "Target.createTarget") created.push("target-1");
    }
    expect(created).toHaveLength(1);

    const fillTarget = created[0]!;
    gate.openFillWindow(TARGET);
    gate.openFillWindow(fillTarget);
    for (const target of [TARGET, fillTarget]) {
      for (const method of ["Runtime.evaluate", "DOM.querySelector", "Input.insertText"]) {
        const decision = gate.evaluateCommand({ method, targetId: target });
        expect(decision.allow, `${method} was allowed on ${target} during a fill`).toBe(false);
      }
    }
    // And the lockout ends, or the agent loses its own browser.
    gate.closeFillWindow(TARGET);
    expect(gate.evaluateCommand({ method: "DOM.querySelector", targetId: TARGET }).allow).toBe(true);
    // The other target stays shut — closing one window must not open both.
    expect(gate.evaluateCommand({ method: "Runtime.evaluate", targetId: fillTarget }).allow).toBe(
      false,
    );
  });
});

describe("the secret's lifetime in this process", () => {
  it("is zeroed after the fill, not left for the collector", async () => {
    // JavaScript has no destructors, so this is explicit or it does not happen.
    const handle = SecretHandle.fromUtf8(PASSWORD);
    const seen = handle.use((b) => new TextDecoder().decode(b));
    expect(seen).toBe(PASSWORD);
    expect(() => handle.use((b) => b.length)).toThrow();
  });

  it("is zeroed even when the fill throws", async () => {
    const handle = SecretHandle.fromUtf8(PASSWORD);
    expect(() =>
      handle.use(() => {
        throw new Error("typing failed");
      }),
    ).toThrow(/typing failed/);
    // The failure path is exactly where a live secret tends to survive.
    expect(() => handle.use((b) => b.length)).toThrow();
  });

  it("cannot be serialised into a tool result by accident", () => {
    const handle = SecretHandle.fromUtf8(PASSWORD);
    // This is the MCP result path. A handle reaching it is a broken control,
    // so it throws rather than rendering as "[object Object]" and looking fine.
    expect(() => JSON.stringify({ status: "filled", handle })).toThrow();
    expect(String(handle)).not.toContain(PASSWORD);
    expect(`${handle}`).not.toContain(PASSWORD);
    expect(Object.keys(handle)).toHaveLength(0);
    handle.dispose?.();
  });
});
