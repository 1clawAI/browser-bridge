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
  const opts = {
    baseUrl: "https://api.1claw.co",
    bridgeCredential: "bb_test",
    userToken: "user_test",
    agentToken: "agent_test",
    agentId: "00000000-0000-0000-0000-0000000000aa",
    bridgeVersion: "0.1.0",
  };
  const driver = new SaasDriver({ ...opts, fetch: async () => new Response("{}", { status: 200 }) });

  const openedSession = (fetchImpl: typeof globalThis.fetch) =>
    new SaasDriver({ ...opts, fetch: fetchImpl });

  it("declares registration off until v0.2 ships its adversarial suite", () => {
    expect(driver.capabilities().registration).toBe(false);
  });

  it("declares only the capabilities the vault has routes for", () => {
    // A capability advertised ahead of its endpoint registers a tool that 404s
    // on first call, which teaches an agent to retry against a missing route.
    const caps = driver.capabilities();
    expect(caps.fills).toBe(true);
    for (const off of ["checkout", "signing", "hitl", "shadowReports"] as const) {
      expect(caps[off]).toBe(false);
    }
  });

  it("does not implement capability-gated methods it does not declare", () => {
    // Implementing them while declaring the capability false is how a gate ends
    // up bypassable by a caller that ignores capabilities().
    const present = driver as unknown as Record<string, unknown>;
    expect(present.beginRegistration).toBeUndefined();
    expect(present.commitRegistration).toBeUndefined();
  });

  it("sends the bridge credential as its own header, never as the bearer or in a URL", async () => {
    let seen: { url: string; init: RequestInit } | null = null;
    const d = openedSession(async (url, init) => {
      seen = { url: String(url), init: init as RequestInit };
      return new Response(
        JSON.stringify({ session_id: "s1", session_token: "bs_tok", expires_at: "" }),
        { status: 200 },
      );
    });
    await d.openSession({ clientId: "c1", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
    const headers = seen!.init.headers as Record<string, string>;
    // The device credential and the principal authenticate different things, so
    // they travel separately. Sending bb_ as the bearer would ask the vault to
    // resolve it as a principal, which it is not.
    expect(headers["x-1claw-bridge-credential"]).toBe("bb_test");
    expect(headers.authorization).toBe("Bearer user_test");
    expect(headers["x-1claw-protocol-version"]).toBe("0.1.0");
    // A credential in a query string lands in access logs and referrers.
    expect(seen!.url).not.toContain("bb_test");
    expect(seen!.url).not.toContain("bs_tok");
  });

  it("opens a session with the user's token and asks for fills with the agent's", async () => {
    // Two credentials because the vault requires two: it refuses a session
    // opened by an agent, and refuses a fill that does not name one.
    const bearers: string[] = [];
    const d = openedSession(async (_url, init) => {
      const h = (init as RequestInit).headers as Record<string, string>;
      bearers.push(h.authorization ?? "");
      return new Response(
        JSON.stringify({
          session_id: "s1",
          session_token: "bs_tok",
          expires_at: "",
          kind: "grant",
          grant_id: "g1",
          binding_id: "b1",
          login_url: "https://example.com/login",
        }),
        { status: 200 },
      );
    });
    await d.openSession({ clientId: "c1", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
    await d.authorizeFill({
      sessionId: "s1", bindingId: "b1",
      tabOrigin: "https://example.com", frameOrigin: "https://example.com",
      formActionOrigin: "https://example.com", frameId: "T1", generation: 1,
    });
    expect(bearers).toEqual(["Bearer user_test", "Bearer agent_test"]);
  });

  it("collects the secret with the user's token, not the agent's", async () => {
    // The agent asks which binding; it does not get to hold the answer. If this
    // sent the agent token the vault would refuse, but sending it at all would
    // mean the bridge had tried.
    let bearer = "";
    const d = openedSession(async (_url, init) => {
      const h = (init as RequestInit).headers as Record<string, string>;
      bearer = h.authorization ?? "";
      return new Response(
        JSON.stringify({ session_id: "s1", session_token: "bs_tok", expires_at: "" }),
        { status: 200 },
      );
    });
    await d.openSession({ clientId: "c1", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
    await d.consumeFill({
      kind: "grant", grantId: "g1", bindingId: "b1",
      loginUrl: "https://example.com/login", expiresAt: "", generation: 1,
    });
    expect(bearer).toBe("Bearer user_test");
  });

  it("sends the session id in the body and the session token in the header", async () => {
    // They are different values and the vault checks both: the body's id must
    // match the session the token resolves to. Sending the token where the id
    // belongs fails every fill, and does so at the wire rather than at compile
    // time — which is exactly the bug this pins.
    let body: Record<string, unknown> = {};
    let header = "";
    let call = 0;
    const d = openedSession(async (_url, init) => {
      call += 1;
      const i = init as RequestInit;
      if (call > 1) {
        body = JSON.parse(String(i.body));
        header = (i.headers as Record<string, string>)["x-1claw-bridge-session"] ?? "";
      }
      return call === 1
        ? new Response(
            JSON.stringify({ session_id: "sess-uuid", session_token: "bs_tok", expires_at: "" }),
            { status: 200 },
          )
        : new Response(new TextEncoder().encode("pw"), { status: 200 });
    });
    await d.openSession({ clientId: "c1", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
    await d.consumeFill({
      kind: "grant", grantId: "g1", bindingId: "b1",
      loginUrl: "https://example.com/login", expiresAt: "", generation: 1,
    });
    expect(body.session_id).toBe("sess-uuid");
    expect(header).toBe("bs_tok");
    // Never the other way round.
    expect(body.session_id).not.toBe("bs_tok");
  });

  it("takes the consume body as the credential itself, not as an envelope", async () => {
    // The vault returns the raw secret with metadata in headers. If it ever
    // wrapped it in JSON, this handle would hold the wrapper and the bridge
    // would type `{"value":"…"}` into a password field.
    let call = 0;
    const d = openedSession(async () => {
      call += 1;
      return call === 1
        ? new Response(
            JSON.stringify({ session_id: "s1", session_token: "bs_tok", expires_at: "" }),
            { status: 200 },
          )
        : new Response(new TextEncoder().encode("s3cret"), {
            status: 200,
            headers: { "content-type": "application/octet-stream", "x-1claw-binding-id": "b1" },
          });
    });
    await d.openSession({ clientId: "c1", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
    const handle = await d.consumeFill({
      kind: "grant", grantId: "g1", bindingId: "b1",
      loginUrl: "https://example.com/login", expiresAt: "", generation: 1,
    });
    const got = handle.use((b) => new TextDecoder().decode(b));
    expect(got).toBe("s3cret");
    expect(got).not.toContain("{");
  });

  it("refuses to consume before a session is open", async () => {
    // The session token is what binds a redemption to this bridge. Without one
    // there is nothing to present, and asking anyway would send a grant id to
    // the vault with no proof it is ours.
    const d = openedSession(async () => new Response("{}", { status: 200 }));
    await expect(
      d.consumeFill({
        kind: "grant", grantId: "g1", bindingId: "b1",
        loginUrl: "https://example.com/login", expiresAt: "", generation: 1,
      }),
    ).rejects.toThrow(/no open browser session/);
  });

  it("returns consumed fills as a handle, never a string", async () => {
    let call = 0;
    const d = openedSession(async () => {
      call += 1;
      return call === 1
        ? new Response(
            JSON.stringify({ session_id: "s1", session_token: "bs_tok", expires_at: "" }),
            { status: 200 },
          )
        : new Response(new TextEncoder().encode("s3cret"), { status: 200 });
    });
    await d.openSession({ clientId: "c1", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
    const handle = await d.consumeFill({
      kind: "grant", grantId: "g1", bindingId: "b1",
      loginUrl: "https://example.com/login", expiresAt: "", generation: 1,
    });
    expect(typeof handle).not.toBe("string");
    expect(() => JSON.stringify(handle)).toThrow();
    expect(handle.use((b) => new TextDecoder().decode(b))).toBe("s3cret");
  });

  it("does not put the vault's error body into the thrown message unbounded", async () => {
    const d = openedSession(async () => new Response("x".repeat(5000), { status: 500 }));
    const call = () =>
      d.openSession({ clientId: "c1", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
    await expect(call()).rejects.toThrow(/failed \(500\)/);
    await call().catch((e: Error) => {
      expect(e.message.length).toBeLessThan(400);
    });
  });

  it("writes no client-side audit — the vault keeps the chained one", async () => {
    // A second log the machine running the bridge controls, sitting beside one
    // it does not, is worse than no second log.
    let called = false;
    const d = openedSession(async () => {
      called = true;
      return new Response("{}", { status: 200 });
    });
    await d.audit({ kind: "fill", at: new Date().toISOString() } as never);
    expect(called).toBe(false);
  });
});
