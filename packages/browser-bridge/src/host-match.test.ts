// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { hostAllowed, hostOf } from "./host-match.js";

/**
 * The allowlist match, which decides whether a credential may be typed here.
 *
 * It had no tests. Every driver's origin check routes through it — three call
 * sites in the mock backend alone — so a subtle mistake in these forty lines is
 * a credential typed into a lookalike host, which is the failure the whole
 * package exists to prevent. Its rules are documented carefully; these are the
 * assertions that the code does what the documentation promises.
 */
describe("what an allowlist entry matches", () => {
  it("matches a bare entry exactly, and nothing that merely ends with it", () => {
    expect(hostAllowed("https://app.example.com/login", ["app.example.com"])).toBe(true);
    // The one that matters: a suffix match here is a working phishing host.
    expect(hostAllowed("https://evil-app.example.com/", ["app.example.com"])).toBe(false);
    expect(hostAllowed("https://app.example.com.evil.test/", ["app.example.com"])).toBe(false);
    expect(hostAllowed("https://sub.app.example.com/", ["app.example.com"])).toBe(false);
  });

  it("matches the apex and any subdomain when the entry opens with a dot", () => {
    const list = [".example.com"];
    expect(hostAllowed("https://example.com/", list)).toBe(true);
    expect(hostAllowed("https://app.example.com/", list)).toBe(true);
    expect(hostAllowed("https://a.b.example.com/", list)).toBe(true);
    // Still not a suffix match on the string.
    expect(hostAllowed("https://notexample.com/", list)).toBe(false);
    expect(hostAllowed("https://example.com.evil.test/", list)).toBe(false);
  });

  it("treats a lone dot and empty entries as matching nothing", () => {
    for (const list of [["."], [""], ["  "], []]) {
      expect(hostAllowed("https://example.com/", list), JSON.stringify(list)).toBe(false);
    }
  });

  it("ignores case and surrounding whitespace in the entry", () => {
    expect(hostAllowed("https://App.Example.COM/", ["  app.example.com  "])).toBe(true);
    expect(hostAllowed("https://app.example.com/", ["APP.EXAMPLE.COM"])).toBe(true);
  });

  it("accepts if any entry matches", () => {
    expect(hostAllowed("https://b.test/", ["a.test", "b.test", "c.test"])).toBe(true);
  });

  it("does not treat * as a wildcard, because nothing here implements one", () => {
    // An entry the matcher does not understand is stored, matches nothing, and
    // leaves the operator believing a host was allowed. Better it match only
    // itself than silently match everything.
    expect(hostAllowed("https://app.example.com/", ["*.example.com"])).toBe(false);
    expect(hostAllowed("https://anything.test/", ["*"])).toBe(false);
  });
});

describe("reading the host out of an origin", () => {
  it("takes the host after the last @, not the first", () => {
    // https://app.example.com@evil.test/ is a request to evil.test. A matcher
    // that reads the userinfo as the host allows the attacker's page.
    expect(hostOf("https://app.example.com@evil.test/")).toBe("evil.test");
    expect(hostOf("https://a@b@evil.test/")).toBe("evil.test");
    expect(hostAllowed("https://app.example.com@evil.test/", ["app.example.com"])).toBe(false);
    expect(hostAllowed("https://evil.test@app.example.com/", ["app.example.com"])).toBe(true);
  });

  it("drops the port", () => {
    expect(hostOf("http://127.0.0.1:8080/x")).toBe("127.0.0.1");
    expect(hostAllowed("http://app.example.com:8443/", ["app.example.com"])).toBe(true);
  });

  it("reads an IPv6 literal out of its brackets", () => {
    expect(hostOf("http://[::1]:8080/")).toBe("::1");
    expect(hostOf("http://[2001:db8::1]/")).toBe("2001:db8::1");
  });

  it("stops at the first path, query or fragment", () => {
    expect(hostOf("https://example.com/a@evil.test")).toBe("example.com");
    expect(hostOf("https://example.com?x=@evil.test")).toBe("example.com");
    expect(hostOf("https://example.com#@evil.test")).toBe("example.com");
    // The path cannot smuggle a different host past the allowlist.
    expect(hostAllowed("https://evil.test/https://app.example.com", ["app.example.com"])).toBe(
      false,
    );
  });

  it("works without a scheme", () => {
    expect(hostOf("example.com/path")).toBe("example.com");
    expect(hostOf("example.com")).toBe("example.com");
  });

  it("lowercases, so a mixed-case host cannot slip past a lowercase entry", () => {
    expect(hostOf("HTTPS://APP.EXAMPLE.COM/")).toBe("app.example.com");
  });

  it("denies rather than guesses when it cannot read a host", () => {
    // "Not a URL" is not evidence that it is safe.
    for (const bad of ["", "   ", "https://", "http:///path", "://x", "https://@"]) {
      expect(hostAllowed(bad, [".example.com", "example.com"]), JSON.stringify(bad)).toBe(false);
    }
    expect(hostOf("")).toBeUndefined();
    expect(hostOf("https://")).toBeUndefined();
  });

  it("does not let a trailing dot pass as a different host", () => {
    // example.com. and example.com are the same name to DNS. Matching only one
    // of them is a difference between what the operator allowed and what the
    // browser resolves — documented here as the behaviour that exists.
    expect(hostOf("https://example.com./")).toBe("example.com.");
    expect(hostAllowed("https://example.com./", ["example.com"])).toBe(false);
  });
});
