// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { Capabilities } from "@1claw/browser-bridge-protocol";
import { CAPABILITY_TOOLS, toolsFor } from "./vault-backend.js";
import { SaasDriver } from "./drivers/saas.js";

const SAAS: Capabilities = {
  fills: true, registration: false, checkout: true, signing: true,
  hitl: true, centralAudit: true, shadowReports: true,
};

const COMMUNITY: Capabilities = {
  fills: true, registration: false, checkout: false, signing: false,
  hitl: false, centralAudit: false, shadowReports: false,
};

describe("capability gating", () => {
  it("registers fill tools on every backend — fills are why the bridge exists", () => {
    for (const caps of [SAAS, COMMUNITY]) {
      expect(toolsFor(caps)).toContain("request_fill");
    }
  });

  // Absent, not disabled. A tool that exists and always fails teaches an agent
  // to retry, and puts an upsell in agent-visible output.
  it("omits request_checkout entirely on the community backend", () => {
    const tools = toolsFor(COMMUNITY);
    expect(tools).not.toContain("request_checkout");
    expect(tools.join(" ")).not.toMatch(/checkout|upgrade|signing/i);
  });

  it("omits registration tools until the capability is real", () => {
    for (const caps of [SAAS, COMMUNITY]) {
      expect(toolsFor(caps)).not.toContain("begin_credential_registration");
    }
    expect(toolsFor({ ...SAAS, registration: true })).toContain("begin_credential_registration");
  });

  it("maps every capability to a decided tool list", () => {
    const declared = Object.keys(CAPABILITY_TOOLS).sort();
    expect(declared).toEqual(Object.keys(SAAS).sort());
  });

  it("returns a stable, sorted list so tool order cannot leak backend identity", () => {
    expect(toolsFor(SAAS)).toEqual([...toolsFor(SAAS)].sort());
  });
});

describe("SaasDriver", () => {
  const driver = new SaasDriver({
    baseUrl: "https://api.1claw.co",
    bridgeCredential: "bb_test",
    bridgeVersion: "0.1.0",
    fetch: async () => new Response("{}", { status: 200 }),
  });

  it("declares registration off until v0.2 ships its adversarial suite", () => {
    expect(driver.capabilities().registration).toBe(false);
  });

  it("does not implement capability-gated methods it does not declare", () => {
    // Implementing them while declaring the capability false is how a gate ends
    // up bypassable by a caller that ignores capabilities().
    expect(driver.beginRegistration).toBeUndefined();
    expect(driver.commitRegistration).toBeUndefined();
  });

  it("sends the bridge credential and protocol version, and never in a URL", async () => {
    let seen: { url: string; init: RequestInit } | null = null;
    const d = new SaasDriver({
      baseUrl: "https://api.1claw.co",
      bridgeCredential: "bb_secret_value",
      bridgeVersion: "0.1.0",
      fetch: async (url, init) => {
        seen = { url: String(url), init: init as RequestInit };
        return new Response(JSON.stringify({ id: "s1", createdAt: "", expiresAt: "" }), { status: 200 });
      },
    });
    await d.openSession({ clientId: "c1", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
    const headers = seen!.init.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer bb_secret_value");
    expect(headers["x-1claw-protocol-version"]).toBe("0.1.0");
    // A credential in a query string lands in access logs and referrers.
    expect(seen!.url).not.toContain("bb_secret_value");
  });

  it("returns consumed fills as a handle, never a string", async () => {
    const d = new SaasDriver({
      baseUrl: "https://api.1claw.co",
      bridgeCredential: "bb_test",
      bridgeVersion: "0.1.0",
      fetch: async () => new Response(new TextEncoder().encode("s3cret"), { status: 200 }),
    });
    const handle = await d.consumeFill({
      kind: "grant", grantId: "g1", bindingId: "b1",
      loginUrl: "https://example.com/login", expiresAt: "", generation: 1,
    });
    expect(typeof handle).not.toBe("string");
    expect(() => JSON.stringify(handle)).toThrow();
    expect(handle.use((b) => new TextDecoder().decode(b))).toBe("s3cret");
  });

  it("does not put the vault's error body into the thrown message unbounded", async () => {
    const d = new SaasDriver({
      baseUrl: "https://api.1claw.co",
      bridgeCredential: "bb_test",
      bridgeVersion: "0.1.0",
      fetch: async () => new Response("x".repeat(5000), { status: 500 }),
    });
    await expect(d.policySnapshot()).rejects.toThrow(/failed \(500\)/);
    await d.policySnapshot().catch((e: Error) => {
      expect(e.message.length).toBeLessThan(400);
    });
  });
});
