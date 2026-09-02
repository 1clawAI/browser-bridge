// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generatePassword, satisfies, DEFAULT_PASSWORD_POLICY } from "./password-gen.js";

describe("generated passwords", () => {
  it("satisfies its own policy every time", () => {
    // By construction, not by luck: a flaky generator produces a password the
    // site rejects, and the failure surfaces as a broken account weeks later.
    for (let i = 0; i < 500; i++) {
      expect(satisfies(generatePassword())).toBe(true);
    }
  });

  it("honours a policy that forbids symbols", () => {
    const set = new Set(DEFAULT_PASSWORD_POLICY.symbols.split(""));
    for (let i = 0; i < 200; i++) {
      const pw = generatePassword({ symbols: "" });
      expect([...pw].some((c) => set.has(c)), pw).toBe(false);
    }
  });

  it("honours a length", () => {
    expect(generatePassword({ length: 32 })).toHaveLength(32);
  });

  it("excludes confusable characters", () => {
    // These get read aloud and typed by hand during account recovery.
    for (let i = 0; i < 200; i++) {
      expect(generatePassword()).not.toMatch(/[lIO01]/);
    }
  });

  it("does not repeat itself", () => {
    const seen = new Set(Array.from({ length: 500 }, () => generatePassword()));
    expect(seen.size).toBe(500);
  });

  it("is roughly uniform, so there is no modulo bias", () => {
    // `bytes[i] % n` skews toward the low end of the alphabet. randomInt does
    // not. With 20k draws a 2x skew would be obvious; this asserts nothing
    // stronger than "no class is starved".
    const counts = new Map<string, number>();
    for (let i = 0; i < 2000; i++) {
      for (const c of generatePassword({ length: 10 })) {
        counts.set(c, (counts.get(c) ?? 0) + 1);
      }
    }
    const values = [...counts.values()];
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    for (const v of values) {
      expect(v).toBeGreaterThan(mean * 0.4);
      expect(v).toBeLessThan(mean * 1.9);
    }
  });

  it("refuses a policy nothing can satisfy", () => {
    expect(() => generatePassword({ lower: false, upper: false, digits: false, symbols: "" }))
      .toThrow(/permits no characters/);
    expect(() => generatePassword({ length: 2 })).toThrow();
  });

  it("refuses to generate something too short to matter", () => {
    // If a site demands this, a human should notice rather than the bridge
    // quietly complying.
    expect(() => generatePassword({ length: 6 })).toThrow(/shorter than 8/);
  });
});
