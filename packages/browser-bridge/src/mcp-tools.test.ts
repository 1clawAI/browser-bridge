// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import type { Capabilities, FillDecision } from "@1claw/browser-bridge-protocol";
import { buildToolset, dispatchTool, type ToolResult } from "./mcp-tools.js";
import { SecretHandle } from "./secret-handle.js";
import type { VaultBackend } from "./vault-backend.js";

const PASSWORD = "hunter2-correct-horse";

const SAAS: Capabilities = {
  fills: true, registration: false, checkout: true, signing: true,
  hitl: true, centralAudit: true, shadowReports: true,
};
const COMMUNITY: Capabilities = {
  fills: true, registration: false, checkout: false, signing: false,
  hitl: false, centralAudit: false, shadowReports: false,
};

const GRANT: FillDecision = {
  kind: "grant", grantId: "g1", bindingId: "b1",
  loginUrl: "https://app.example.com/login", expiresAt: "", generation: 1,
};

function backend(caps: Capabilities, decision: FillDecision = GRANT): VaultBackend {
  return {
    capabilities: () => caps,
    openSession: async () => ({ id: "s1", createdAt: "", expiresAt: "" }),
    closeSession: async () => {},
    authorizeFill: async () => decision,
    consumeFill: async () => SecretHandle.fromUtf8(PASSWORD),
    audit: async () => {},
    policySnapshot: async () => ({ policyHash: "", capturedAt: "", allowedHosts: [], ssoHosts: [] }),
  };
}

const ctx = (b: VaultBackend, execute?: (d: FillDecision) => Promise<ToolResult>) => ({
  backend: b,
  sessionId: "s1",
  execute:
    execute ??
    (async (d: FillDecision) => {
      // What the real engine does: consume, type, never return the value.
      const handle = await b.consumeFill(d as never);
      handle.use(() => {});
      return { status: "filled", bindingId: "b1" } as ToolResult;
    }),
  observe: () => ({
    tabOrigin: "https://app.example.com",
    frameOrigin: "https://app.example.com",
    formActionOrigin: "https://app.example.com",
    frameId: "frame-1",
    generation: 1,
  }),
});

describe("the surface an agent sees", () => {
  it("offers fill tools on every backend", () => {
    for (const caps of [SAAS, COMMUNITY]) {
      expect(buildToolset(caps).map((t) => t.name)).toContain("request_fill");
    }
  });

  it("omits checkout entirely on community — absent, not disabled", () => {
    const names = buildToolset(COMMUNITY).map((t) => t.name);
    expect(names).not.toContain("request_checkout");
    expect(JSON.stringify(buildToolset(COMMUNITY))).not.toMatch(/upgrade|checkout|signature/i);
  });

  /**
   * The schema is the boundary. If request_fill accepted a url, an agent could
   * choose which page receives the credential; if it accepted a value, the
   * agent would be supplying the secret. Neither is a field here.
   */
  it("accepts only a binding id — no url, no value, no username", () => {
    const fill = buildToolset(SAAS).find((t) => t.name === "request_fill")!;
    const props = Object.keys((fill.inputSchema as { properties: object }).properties);
    expect(props).toEqual(["binding_id"]);
    expect((fill.inputSchema as { additionalProperties: boolean }).additionalProperties).toBe(false);
  });

  it("describes the fill tool without implying it returns a credential", () => {
    const fill = buildToolset(SAAS).find((t) => t.name === "request_fill")!;
    expect(fill.description).toMatch(/never the credential/i);
  });
});

describe("dispatch never yields credential material", () => {
  // The property that matters most. Whatever the path, the serialised result
  // must not contain the secret.
  it("returns a status, not the password, on a successful fill", async () => {
    const b = backend(SAAS);
    const result = await dispatchTool("request_fill", { binding_id: "b1" }, ctx(b));
    expect(result).toEqual({ status: "filled", bindingId: "b1" });
    expect(JSON.stringify(result)).not.toContain(PASSWORD);
  });

  it("cannot be made to serialise a handle even if an executor tries", async () => {
    const b = backend(SAAS);
    const leaky = async (d: FillDecision) => {
      const handle = await b.consumeFill(d as never);
      // A careless executor hands the handle back. The result type has nowhere
      // to put it, and serialising it throws rather than leaking.
      return { status: "filled", bindingId: "b1", handle } as unknown as ToolResult;
    };
    const result = await dispatchTool("request_fill", { binding_id: "b1" }, ctx(b, leaky));
    expect(() => JSON.stringify(result)).toThrow(/never reach a tool result/);
  });

  it("passes a denial through as a closed-set reason, not free text", async () => {
    const denied: FillDecision = {
      kind: "denied", reason: "frame_origin_mismatch", message: "an iframe on evil.example",
    };
    const result = await dispatchTool("request_fill", { binding_id: "b1" }, ctx(backend(SAAS, denied)));
    expect(result).toEqual({ status: "denied", reason: "frame_origin_mismatch" });
    // The human-readable detail is for the audit log, not for the agent.
    expect(JSON.stringify(result)).not.toContain("evil.example");
  });

  it("surfaces a pending approval without leaking what is being approved", async () => {
    const pending: FillDecision = {
      kind: "awaiting_approval", approvalId: "ap1", pollAfterMs: 2000,
    };
    const result = await dispatchTool("request_fill", { binding_id: "b1" }, ctx(backend(SAAS, pending)));
    expect(result).toEqual({ status: "awaiting_approval", approvalId: "ap1", pollAfterMs: 2000 });
  });
});

describe("dispatch refuses what it should", () => {
  it("rejects a tool the backend does not offer, with the same answer as unknown", async () => {
    const result = await dispatchTool("request_checkout", { binding_id: "b1" }, ctx(backend(COMMUNITY)));
    expect(result.status).toBe("error");
    // Not "upgrade your plan": whether a capability exists is not the agent's
    // business, and the two cases must be indistinguishable.
    expect(JSON.stringify(result)).toMatch(/unknown tool/);
  });

  it("rejects an unknown tool name", async () => {
    const result = await dispatchTool("exfiltrate", {}, ctx(backend(SAAS)));
    expect(result.status).toBe("error");
  });

  it("requires a binding id", async () => {
    const result = await dispatchTool("request_fill", {}, ctx(backend(SAAS)));
    expect(result).toEqual({ status: "error", message: "binding_id is required" });
  });

  // Page state is observed by the bridge, never accepted from the agent.
  it("ignores any origin the agent tries to supply", async () => {
    const b = backend(SAAS);
    const spy = vi.spyOn(b, "authorizeFill");
    await dispatchTool(
      "request_fill",
      { binding_id: "b1", tab_origin: "https://evil.example", frame_origin: "https://evil.example" },
      ctx(b),
    );
    const passed = spy.mock.calls[0]![0];
    expect(passed.tabOrigin).toBe("https://app.example.com");
    expect(passed.frameOrigin).toBe("https://app.example.com");
  });
});
