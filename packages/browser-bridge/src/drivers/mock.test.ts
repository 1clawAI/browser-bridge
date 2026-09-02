// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { MockVaultDriver, type MockBinding } from "./mock.js";
import type { FillRequest } from "@1claw/browser-bridge-protocol";

const SECRET = "hunter2-mock";
const BINDING: MockBinding = {
  id: "b1",
  secret: SECRET,
  loginUrl: "https://app.example.com/login",
  allowedHosts: ["app.example.com"],
};

function driver(over: Partial<ConstructorParameters<typeof MockVaultDriver>[0]> = {}) {
  return new MockVaultDriver({ bindings: [BINDING], ...over });
}

const req = (over: Partial<FillRequest> = {}): FillRequest => ({
  sessionId: "s1",
  bindingId: "b1",
  tabOrigin: "https://app.example.com",
  frameOrigin: "https://app.example.com",
  formActionOrigin: "https://app.example.com",
  frameId: "T1",
  generation: 1,
  ...over,
});

async function opened(over = {}) {
  const d = driver(over);
  await d.openSession({ clientId: "c", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
  return d;
}

describe("the mock backend refuses what the hosted one refuses", () => {
  // If this driver were more permissive, the demo would teach a rule the real
  // backend does not follow — worse than having no demo.

  it("allows the binding's own host", async () => {
    const d = await opened();
    expect((await d.authorizeFill(req())).kind).toBe("grant");
  });

  it("refuses a lookalike host", async () => {
    const d = await opened();
    for (const bad of [
      "https://evil-app.example.com",
      "https://app.example.com.evil.test",
      "https://sub.app.example.com",
    ]) {
      const out = await d.authorizeFill(req({ tabOrigin: bad, frameOrigin: bad, formActionOrigin: bad }));
      expect(out.kind, bad).toBe("denied");
    }
  });

  it("honours a leading-dot entry as the subdomain syntax", async () => {
    const d = new MockVaultDriver({
      bindings: [{ ...BINDING, allowedHosts: [".example.com"] }],
    });
    await d.openSession({ clientId: "c", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
    for (const ok of ["https://app.example.com", "https://example.com", "https://a.b.example.com"]) {
      const out = await d.authorizeFill(req({ tabOrigin: ok, frameOrigin: ok, formActionOrigin: ok }));
      expect(out.kind, ok).toBe("grant");
    }
  });

  it("is not fooled by userinfo in the authority", async () => {
    // https://allowed@evil.test/ resolves to evil.test, not to the allowed host.
    const d = await opened();
    const bad = "https://app.example.com@evil.test/login";
    const out = await d.authorizeFill(req({ tabOrigin: bad, frameOrigin: bad, formActionOrigin: bad }));
    expect(out.kind).toBe("denied");
  });

  it("checks the frame and the form action separately from the tab", async () => {
    const d = await opened();
    const iframe = await d.authorizeFill(req({ frameOrigin: "https://evil.test" }));
    expect(iframe).toMatchObject({ kind: "denied", reason: "frame_origin_mismatch" });
    const posts = await d.authorizeFill(req({ formActionOrigin: "https://evil.test" }));
    expect(posts).toMatchObject({ kind: "denied", reason: "form_action_not_allowed" });
  });

  it("does not say whether an unknown binding exists", async () => {
    // Same answer as "not allowed": which credentials exist is not something an
    // agent gets to enumerate.
    const d = await opened();
    const out = await d.authorizeFill(req({ bindingId: "nope" }));
    expect(out).toMatchObject({ kind: "denied", reason: "policy_denied" });
  });

  it("refuses a fill with no open session", async () => {
    const d = driver();
    expect(await d.authorizeFill(req())).toMatchObject({ kind: "denied", reason: "session_expired" });
  });

  it("caps repeated fills of one binding", async () => {
    const d = await opened({ velocityLimit: 3 });
    for (let i = 0; i < 3; i++) expect((await d.authorizeFill(req())).kind).toBe("grant");
    expect(await d.authorizeFill(req())).toMatchObject({
      kind: "denied",
      reason: "velocity_exceeded",
    });
  });
});

describe("the mock backend's grants", () => {
  it("hands the secret back exactly once", async () => {
    const d = await opened();
    const grant = await d.authorizeFill(req());
    if (grant.kind !== "grant") throw new Error("expected a grant");

    const handle = await d.consumeFill(grant);
    expect(handle.use((b) => new TextDecoder().decode(b))).toBe(SECRET);
    await expect(d.consumeFill(grant)).rejects.toThrow(/unknown or already redeemed/);
  });

  it("spends a grant even when redemption then fails", async () => {
    // Single-use must mean "used", not "used successfully". A grant returned to
    // the pool by a later error is a grant that can be retried.
    const d = await opened();
    const grant = await d.authorizeFill(req());
    if (grant.kind !== "grant") throw new Error("expected a grant");

    await expect(d.consumeFill({ ...grant, generation: 99 })).rejects.toThrow(/navigated/);
    await expect(d.consumeFill(grant)).rejects.toThrow(/unknown or already redeemed/);
  });

  it("refuses a grant issued for a page that has since moved", async () => {
    const d = await opened();
    const grant = await d.authorizeFill(req({ generation: 4 }));
    if (grant.kind !== "grant") throw new Error("expected a grant");
    await expect(d.consumeFill({ ...grant, generation: 5 })).rejects.toThrow(/navigated/);
  });

  it("refuses a grant past its TTL", async () => {
    const d = await opened({ grantTtlSeconds: 0 });
    const grant = await d.authorizeFill(req());
    if (grant.kind !== "grant") throw new Error("expected a grant");
    await new Promise((r) => setTimeout(r, 5));
    await expect(d.consumeFill(grant)).rejects.toThrow(/expired/);
  });

  it("returns a handle, not a string", async () => {
    const d = await opened();
    const grant = await d.authorizeFill(req());
    if (grant.kind !== "grant") throw new Error("expected a grant");
    const handle = await d.consumeFill(grant);
    expect(() => JSON.stringify(handle)).toThrow();
    expect(String(handle)).not.toContain(SECRET);
  });

  it("advertises only fills, so no other tool is registered", async () => {
    const caps = driver().capabilities();
    expect(caps.fills).toBe(true);
    for (const off of ["registration", "checkout", "signing", "hitl", "shadowReports"] as const) {
      expect(caps[off], off).toBe(false);
    }
  });
});
