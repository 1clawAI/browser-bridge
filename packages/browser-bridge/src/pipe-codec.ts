// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import type { CdpMessage } from "./cdp-transport.js";

/**
 * Framing for CDP over `--remote-debugging-pipe`.
 *
 * Chromium writes JSON messages separated by a NUL byte. That is the entire
 * protocol, and it is exactly the shape that invites a class of bug which only
 * appears under load: a pipe delivers *bytes*, not messages. One read can carry
 * half a message, or three messages, or two and a half — and a decoder that
 * assumes one chunk is one message works perfectly against small test payloads
 * and corrupts the first large DOM snapshot it meets in production.
 *
 * So the decoder is a buffer with a boundary scan, and the tests deliberately
 * split messages at awkward points, including mid-UTF-8-sequence.
 */

const NUL = 0x00;

/** Encode one message for the write pipe. */
export function encodeMessage(msg: CdpMessage): Buffer {
  return Buffer.concat([Buffer.from(JSON.stringify(msg), "utf8"), Buffer.from([NUL])]);
}

/**
 * Accumulates bytes from the read pipe and yields whole messages.
 *
 * Stateful on purpose: the leftover between chunks is the whole point.
 */
export class PipeDecoder {
  #buffer: Buffer = Buffer.alloc(0);
  readonly #maxMessageBytes: number;

  /**
   * @param maxMessageBytes Refuse to buffer beyond this. A pipe that never
   * delivers a NUL would otherwise grow the buffer until the process dies, and
   * "the bridge ran out of memory" is a poor way to learn the peer is broken.
   */
  constructor(maxMessageBytes = 64 * 1024 * 1024) {
    this.#maxMessageBytes = maxMessageBytes;
  }

  /** Feed bytes; get back whatever complete messages they completed. */
  push(chunk: Buffer): CdpMessage[] {
    this.#buffer = this.#buffer.length === 0 ? chunk : Buffer.concat([this.#buffer, chunk]);

    const out: CdpMessage[] = [];
    let start = 0;
    for (;;) {
      const end = this.#buffer.indexOf(NUL, start);
      if (end === -1) break;
      const slice = this.#buffer.subarray(start, end);
      start = end + 1;
      // A NUL with nothing before it is a keepalive, not a message.
      if (slice.length === 0) continue;
      // Decoding happens on a whole message, so a multi-byte character split
      // across chunks has already been reassembled by the time we get here.
      out.push(JSON.parse(slice.toString("utf8")) as CdpMessage);
    }

    this.#buffer = start === 0 ? this.#buffer : this.#buffer.subarray(start);

    if (this.#buffer.length > this.#maxMessageBytes) {
      const size = this.#buffer.length;
      this.#buffer = Buffer.alloc(0);
      throw new Error(
        `CDP pipe message exceeded ${this.#maxMessageBytes} bytes (buffered ${size}) — ` +
          `the peer is not framing messages`,
      );
    }

    return out;
  }

  /** Bytes held pending a boundary. Exposed for tests and diagnostics. */
  get pending(): number {
    return this.#buffer.length;
  }
}
