// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { SecretHandle } from "./secret-handle.js";

const PLAINTEXT = "hunter2-correct-horse-battery-staple";

describe("SecretHandle", () => {
  it("gives the bytes to a borrower and zeroes them afterwards", () => {
    const h = SecretHandle.fromUtf8(PLAINTEXT);
    const seen = h.use((b) => new TextDecoder().decode(b));
    expect(seen).toBe(PLAINTEXT);
    expect(h.disposed).toBe(true);
  });

  // The failure path is exactly where a live secret is most likely to be left
  // behind while an error propagates.
  it("zeroes even when the borrower throws", () => {
    const h = SecretHandle.fromUtf8(PLAINTEXT);
    expect(() => h.use(() => { throw new Error("fill failed"); })).toThrow("fill failed");
    expect(h.disposed).toBe(true);
  });

  it("actually overwrites the buffer rather than dropping the reference", () => {
    const bytes = new TextEncoder().encode(PLAINTEXT);
    const h = SecretHandle.adopt(bytes);
    h.dispose();
    expect(Array.from(bytes).every((b) => b === 0)).toBe(true);
  });

  it("refuses to be read after disposal", () => {
    const h = SecretHandle.fromUtf8(PLAINTEXT);
    h.dispose();
    expect(() => h.peek(() => 1)).toThrow(/disposed/);
  });

  it("disposes idempotently", () => {
    const h = SecretHandle.fromUtf8(PLAINTEXT);
    h.dispose();
    expect(() => h.dispose()).not.toThrow();
  });

  it("supports `using` via Symbol.dispose", () => {
    let captured: SecretHandle;
    {
      using h = SecretHandle.fromUtf8(PLAINTEXT);
      captured = h;
      expect(h.disposed).toBe(false);
    }
    expect(captured!.disposed).toBe(true);
  });

  it("keeps peek() usable across a multi-step fill", () => {
    const h = SecretHandle.fromUtf8(PLAINTEXT);
    expect(h.peek((b) => b.byteLength)).toBe(PLAINTEXT.length);
    expect(h.peek((b) => b.byteLength)).toBe(PLAINTEXT.length);
    expect(h.disposed).toBe(false);
    h.dispose();
  });
});

/**
 * The invariant, stated as tests: a secret must not be able to leave the
 * process through any of the paths a plain string would take.
 */
describe("SecretHandle does not leak through", () => {
  it("JSON.stringify — and fails loudly, because that is the MCP result path", () => {
    const h = SecretHandle.fromUtf8(PLAINTEXT);
    expect(() => JSON.stringify(h)).toThrow(/never reach a tool result/);
    expect(() => JSON.stringify({ result: { credential: h } })).toThrow(/never reach a tool result/);
  });

  // Logging paths redact instead of throwing: a logger that throws takes the
  // caller down with it, and the goal is a useless log line, not an outage.
  it("String(), template interpolation and .toString()", () => {
    const h = SecretHandle.fromUtf8(PLAINTEXT);
    for (const rendered of [String(h), `${h}`, h.toString()]) {
      expect(rendered).not.toContain(PLAINTEXT);
      expect(rendered).toContain("redacted");
    }
  });

  it("util.inspect, which is what console.log uses", () => {
    const h = SecretHandle.fromUtf8(PLAINTEXT);
    for (const rendered of [inspect(h), inspect({ nested: { h } }, { depth: 5 })]) {
      expect(rendered).not.toContain(PLAINTEXT);
      expect(rendered).toContain("redacted");
    }
  });

  it("an Error message built from it", () => {
    const h = SecretHandle.fromUtf8(PLAINTEXT);
    const err = new Error(`fill failed for ${h}`);
    expect(err.message).not.toContain(PLAINTEXT);
    expect(String(err.stack)).not.toContain(PLAINTEXT);
  });

  it("Object.keys / spread — the bytes are a true private field", () => {
    const h = SecretHandle.fromUtf8(PLAINTEXT);
    expect(Object.keys(h)).toEqual([]);
    expect(JSON.stringify(Object.assign({}, h))).not.toContain(PLAINTEXT);
    expect(Object.getOwnPropertyNames(h)).toEqual([]);
  });

  it("its own label and length, which are safe to log", () => {
    const h = SecretHandle.fromUtf8(PLAINTEXT, "binding:abc");
    expect(h.label).toBe("binding:abc");
    expect(h.byteLength).toBe(PLAINTEXT.length);
    expect(inspect(h)).toContain("binding:abc");
    expect(inspect(h)).not.toContain(PLAINTEXT);
  });
});
