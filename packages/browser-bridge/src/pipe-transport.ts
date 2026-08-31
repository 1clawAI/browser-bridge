// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { spawn, type ChildProcess } from "node:child_process";
import type { Writable, Readable } from "node:stream";
import type { CdpMessage, CdpTransport } from "./cdp-transport.js";
import { PipeDecoder, encodeMessage } from "./pipe-codec.js";

/**
 * CDP over `--remote-debugging-pipe`.
 *
 * A debugging *port* is the obvious alternative and the wrong one: it is a
 * localhost socket, and every page the bridge is driving can reach localhost.
 * A page that finds the port gets a full-privilege CDP session to the browser
 * it is running inside — which is precisely the attack the whole CDP-ownership
 * design exists to prevent. The pipe is a pair of file descriptors inherited by
 * this process alone; nothing else on the machine can address it.
 *
 * Chromium is launched with stdio positions 3 and 4 wired to pipes: it reads
 * commands from fd 3 and writes to fd 4.
 */

export type PipeTransportOptions = {
  readonly executablePath: string;
  readonly args?: readonly string[];
  readonly userDataDir?: string;
  /** Milliseconds before an unanswered command rejects. */
  readonly commandTimeoutMs?: number;
};

type Pending = {
  resolve: (m: CdpMessage) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
};

export class PipeCdpTransport implements CdpTransport {
  readonly #child: ChildProcess;
  readonly #write: Writable;
  readonly #decoder = new PipeDecoder();
  readonly #pending = new Map<number, Pending>();
  readonly #listeners: ((evt: CdpMessage) => void)[] = [];
  readonly #timeoutMs: number;
  #nextId = 1;
  #closed = false;

  private constructor(child: ChildProcess, timeoutMs: number) {
    this.#child = child;
    this.#timeoutMs = timeoutMs;

    // stdio[3] is Chromium's input, stdio[4] its output. Node exposes the
    // extra descriptors on `stdio`, past stdin/stdout/stderr.
    const write = child.stdio[3] as Writable | null;
    const read = child.stdio[4] as Readable | null;
    if (!write || !read) {
      throw new Error("browser was not launched with the CDP pipe on fds 3 and 4");
    }
    this.#write = write;

    read.on("data", (chunk: Buffer) => this.#onData(chunk));
    read.on("error", (e: Error) => this.#failAll(e));
    child.on("exit", (code) =>
      this.#failAll(new Error(`browser exited with code ${code ?? "unknown"}`)),
    );
  }

  /**
   * Adopt an already-spawned process whose fds 3 and 4 are the CDP pipe.
   *
   * Separate from `launch` so the transport can be driven by a supervisor that
   * owns the browser process — and so its framing and correlation can be tested
   * against a stand-in, without the Chromium-only flags `launch` adds.
   */
  static attach(child: ChildProcess, commandTimeoutMs = 30_000): PipeCdpTransport {
    return new PipeCdpTransport(child, commandTimeoutMs);
  }

  /** Launch Chromium with the pipe wired up. */
  static launch(opts: PipeTransportOptions): PipeCdpTransport {
    const args = [
      "--remote-debugging-pipe",
      // No port, ever. See the note above: a port is reachable by the pages
      // being driven, which defeats the entire ownership model.
      "--no-first-run",
      "--no-default-browser-check",
      ...(opts.userDataDir ? [`--user-data-dir=${opts.userDataDir}`] : []),
      ...(opts.args ?? []),
    ];

    const child = spawn(opts.executablePath, args, {
      // 3 and 4 are the CDP pipe. stderr is kept for launch diagnostics;
      // stdout is ignored because Chromium says nothing useful on it.
      stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"],
    });

    return PipeCdpTransport.attach(child, opts.commandTimeoutMs ?? 30_000);
  }

  async send(msg: CdpMessage): Promise<CdpMessage> {
    if (this.#closed) throw new Error("transport is closed");
    const id = msg.id ?? this.#nextId++;
    const framed = encodeMessage({ ...msg, id });

    return new Promise<CdpMessage>((resolve, reject) => {
      // A command that never gets a reply must not leak a pending entry and a
      // hung caller; a wedged browser should surface as an error, not a hang.
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`CDP command ${msg.method ?? id} timed out after ${this.#timeoutMs}ms`));
      }, this.#timeoutMs);
      timer.unref?.();

      this.#pending.set(id, { resolve, reject, timer });
      this.#write.write(framed, (err) => {
        if (err) {
          clearTimeout(timer);
          this.#pending.delete(id);
          reject(err);
        }
      });
    });
  }

  onEvent(listener: (evt: CdpMessage) => void): void {
    this.#listeners.push(listener);
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.#failAll(new Error("transport closed"));
    this.#child.kill();
  }

  #onData(chunk: Buffer): void {
    let messages: CdpMessage[];
    try {
      messages = this.#decoder.push(chunk);
    } catch (e) {
      // A framing failure means the stream is no longer trustworthy; carrying
      // on would deliver whatever happened to parse next.
      this.#failAll(e instanceof Error ? e : new Error(String(e)));
      return;
    }

    for (const msg of messages) {
      if (msg.id !== undefined && this.#pending.has(msg.id)) {
        const p = this.#pending.get(msg.id)!;
        this.#pending.delete(msg.id);
        clearTimeout(p.timer);
        p.resolve(msg);
      } else {
        for (const l of this.#listeners) l(msg);
      }
    }
  }

  #failAll(err: Error): void {
    for (const [, p] of this.#pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.#pending.clear();
  }
}
