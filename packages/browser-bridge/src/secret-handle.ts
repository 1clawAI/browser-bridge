// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { inspect } from "node:util";

/**
 * A secret the bridge holds transiently, and which must never leave the process.
 *
 * The whole design rests on one invariant: *no driver can return a secret
 * through an MCP tool result*. A string cannot enforce that — it serialises, it
 * logs, it lands in a stack trace, it ends up in an error message someone
 * forwards. This class is the enforcement point, so it is deliberately hostile
 * to every path a string would take out of the process:
 *
 *   - `toJSON` **throws**. JSON.stringify is the MCP serialisation path, so a
 *     handle reaching it is a bug in a security control, not a formatting
 *     problem. It fails loudly rather than emitting a placeholder that would
 *     let the bug ship.
 *   - `toString`, template interpolation and `util.inspect` (which is what
 *     console.log calls) all redact instead of throwing. These are logging
 *     paths, and a logger that throws takes down the caller — the goal is that
 *     an accidental log is useless, not that it is fatal.
 *   - the bytes are zeroed on `dispose()`, and the handle refuses all further
 *     use, so a handle held past its window is inert rather than quietly live.
 *
 * There is no destructor in JavaScript. "Zeroize on drop" is therefore
 * explicit: either `using` (Symbol.dispose) or the `use()` helper, which
 * disposes even if the callback throws. A handle that is merely garbage
 * collected leaves its bytes in memory until the GC reclaims them — that is a
 * real limitation and is why every consume path in the core uses `use()`.
 */
export class SecretHandle {
  #bytes: Uint8Array | null;
  readonly #label: string;

  private constructor(bytes: Uint8Array, label: string) {
    this.#bytes = bytes;
    this.#label = label;
  }

  /**
   * Take ownership of `bytes`. The caller must not keep a reference: this
   * zeroes the same buffer, not a copy.
   */
  static adopt(bytes: Uint8Array, label = "secret"): SecretHandle {
    return new SecretHandle(bytes, label);
  }

  /** Copy a string into a handle. The original string stays in memory until GC. */
  static fromUtf8(value: string, label = "secret"): SecretHandle {
    return new SecretHandle(new TextEncoder().encode(value), label);
  }

  get disposed(): boolean {
    return this.#bytes === null;
  }

  /** Byte length, for velocity accounting and tests. Not secret. */
  get byteLength(): number {
    return this.#bytes?.byteLength ?? 0;
  }

  /** A non-secret name for logs and audit events. */
  get label(): string {
    return this.#label;
  }

  /**
   * Borrow the bytes for the duration of `fn`, then dispose.
   *
   * The handle is disposed even if `fn` throws, because the failure path is
   * exactly where a secret is most likely to be left live while an error
   * propagates.
   */
  use<T>(fn: (bytes: Uint8Array) => T): T {
    const bytes = this.#require();
    try {
      return fn(bytes);
    } finally {
      this.dispose();
    }
  }

  /** Borrow without disposing — for multi-step fills that reuse one credential. */
  peek<T>(fn: (bytes: Uint8Array) => T): T {
    return fn(this.#require());
  }

  /** Overwrite the buffer and refuse all further use. Idempotent. */
  dispose(): void {
    if (this.#bytes) {
      this.#bytes.fill(0);
      this.#bytes = null;
    }
  }

  /** So callers can write `using handle = await backend.consumeFill(grant)`. */
  [Symbol.dispose](): void {
    this.dispose();
  }

  #require(): Uint8Array {
    if (!this.#bytes) {
      throw new Error(`SecretHandle(${this.#label}) has been disposed and cannot be read`);
    }
    return this.#bytes;
  }

  /**
   * Throws. Reaching JSON.stringify means a handle is on its way into an MCP
   * result, which is the one thing the invariant forbids.
   */
  toJSON(): never {
    throw new Error(
      `refusing to serialise SecretHandle(${this.#label}): a secret must never reach a tool result`,
    );
  }

  toString(): string {
    return `[SecretHandle ${this.#label} redacted]`;
  }

  get [Symbol.toStringTag](): string {
    return "SecretHandle";
  }

  /** console.log / util.inspect path — redact rather than throw. */
  [inspect.custom](): string {
    return `[SecretHandle ${this.#label} redacted]`;
  }
}
