// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { PipeDecoder, encodeMessage } from "./pipe-codec.js";

const enc = (o: unknown) => encodeMessage(o as never);

describe("pipe framing", () => {
  it("round-trips a message", () => {
    const d = new PipeDecoder();
    expect(d.push(enc({ id: 1, method: "Page.enable" }))).toEqual([{ id: 1, method: "Page.enable" }]);
    expect(d.pending).toBe(0);
  });

  // A pipe delivers bytes, not messages. This is the case that works in tests
  // with small payloads and corrupts the first large DOM snapshot in production.
  it("reassembles a message split across chunks", () => {
    const d = new PipeDecoder();
    const buf = enc({ id: 2, method: "DOM.getDocument" });
    const mid = Math.floor(buf.length / 2);
    expect(d.push(buf.subarray(0, mid))).toEqual([]);
    expect(d.pending).toBeGreaterThan(0);
    expect(d.push(buf.subarray(mid))).toEqual([{ id: 2, method: "DOM.getDocument" }]);
    expect(d.pending).toBe(0);
  });

  it("yields every message when several arrive in one chunk", () => {
    const d = new PipeDecoder();
    const chunk = Buffer.concat([enc({ id: 1 }), enc({ id: 2 }), enc({ id: 3 })]);
    expect(d.push(chunk)).toEqual([{ id: 1 }, { id: 2 }, { id: 3 }]);
  });

  it("handles two-and-a-half messages, then the rest", () => {
    const d = new PipeDecoder();
    const a = enc({ id: 1 });
    const b = enc({ id: 2 });
    const c = enc({ id: 3 });
    const cut = Math.floor(c.length / 2);
    const first = d.push(Buffer.concat([a, b, c.subarray(0, cut)]));
    expect(first).toEqual([{ id: 1 }, { id: 2 }]);
    expect(d.push(c.subarray(cut))).toEqual([{ id: 3 }]);
  });

  // A split inside a multi-byte character is the subtle one: decoding a
  // half-sequence per chunk would produce replacement characters that never
  // parse back.
  it("survives a split mid-UTF-8-sequence", () => {
    const d = new PipeDecoder();
    const msg = { id: 9, result: { title: "café — 日本語 🔐" } };
    const buf = enc(msg);
    for (let cut = 1; cut < buf.length; cut += 3) {
      const fresh = new PipeDecoder();
      expect(fresh.push(buf.subarray(0, cut))).toEqual([]);
      expect(fresh.push(buf.subarray(cut))).toEqual([msg]);
    }
    expect(d.pending).toBe(0);
  });

  it("byte-by-byte delivery still produces exactly one message", () => {
    const d = new PipeDecoder();
    const buf = enc({ id: 4, method: "Runtime.enable" });
    const seen = [];
    for (const byte of buf) seen.push(...d.push(Buffer.from([byte])));
    expect(seen).toEqual([{ id: 4, method: "Runtime.enable" }]);
  });

  it("ignores empty frames rather than throwing on them", () => {
    const d = new PipeDecoder();
    const chunk = Buffer.concat([Buffer.from([0]), enc({ id: 5 }), Buffer.from([0])]);
    expect(d.push(chunk)).toEqual([{ id: 5 }]);
  });

  it("carries a large payload intact", () => {
    const d = new PipeDecoder();
    const big = { id: 6, result: { html: "x".repeat(2_000_000) } };
    const out = d.push(enc(big));
    expect(out).toHaveLength(1);
    expect((out[0] as typeof big).result.html).toHaveLength(2_000_000);
  });

  // Without a cap, a peer that never sends a NUL grows the buffer until the
  // process dies — a poor way to learn the peer is broken.
  it("refuses to buffer past the cap instead of dying of memory exhaustion", () => {
    const d = new PipeDecoder(1024);
    expect(() => d.push(Buffer.alloc(2048, 0x61))).toThrow(/not framing messages/);
    // It also drops what it had, so the next push starts clean.
    expect(d.pending).toBe(0);
  });

  it("propagates malformed JSON rather than skipping the message silently", () => {
    const d = new PipeDecoder();
    expect(() => d.push(Buffer.concat([Buffer.from("{not json"), Buffer.from([0])]))).toThrow();
  });
});
