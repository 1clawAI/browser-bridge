// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { checkLoopbackRequest } from "./loopback.js";

const TOKEN = "s3ssion-token-abcdefghijklmnop";
const ok = (extra: Record<string, string | undefined> = {}, path = `/cdp/${TOKEN}`) =>
  checkLoopbackRequest({ headers: { host: "127.0.0.1:9222", ...extra }, path }, TOKEN);

describe("loopback listeners", () => {
  it("accepts a local client with a valid token and no Origin", () => {
    expect(ok().ok).toBe(true);
  });

  // The case that matters: a page in the very browser the bridge drives can
  // reach 127.0.0.1, and localhost-to-localhost is *same*-site — so filtering
  // on Sec-Fetch-Site would let it through.
  it("rejects any request carrying an Origin, same-site included", () => {
    for (const origin of ["http://127.0.0.1:3000", "https://evil.example", "http://localhost:8080", "null"]) {
      const r = ok({ origin });
      expect(r.ok, origin).toBe(false);
      if (!r.ok) expect(r.status).toBe(403);
    }
  });

  it("rejects a non-loopback Host, which is how DNS rebinding shows up", () => {
    const r = ok({ host: "evil.example:9222" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/rebinding/);
  });

  it("accepts IPv6 loopback without mangling the bracketed literal", () => {
    expect(ok({ host: "[::1]:9222" }).ok).toBe(true);
  });

  it("rejects a missing Host header rather than defaulting to allow", () => {
    expect(checkLoopbackRequest({ headers: {}, path: `/cdp/${TOKEN}` }, TOKEN).ok).toBe(false);
  });

  // 404, not 403: a wrong token should not confirm a listener is here.
  it("answers a bad token with 404 so the endpoint stays unconfirmed", () => {
    const r = ok({}, "/cdp/wrong-token");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(404);
  });

  it("refuses when the bridge has no token configured", () => {
    const r = checkLoopbackRequest({ headers: { host: "127.0.0.1:9222" }, path: "/cdp/" }, "");
    expect(r.ok).toBe(false);
  });

  it("does not accept a token that merely shares a prefix", () => {
    expect(ok({}, `/cdp/${TOKEN.slice(0, -1)}`).ok).toBe(false);
    expect(ok({}, `/cdp/${TOKEN}x`).ok).toBe(false);
  });

  it("handles header-name casing, since Node lowercases but proxies may not", () => {
    const r = checkLoopbackRequest(
      { headers: { Host: "127.0.0.1:9222", Origin: "https://evil.example" }, path: `/cdp/${TOKEN}` },
      TOKEN,
    );
    expect(r.ok).toBe(false);
  });
});
