// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * The bridge's own connection to Chromium.
 *
 * Kept behind an interface for one reason that matters and one that is merely
 * convenient. The one that matters: the proxy's routing and refusal behaviour
 * is security-critical and must be testable exhaustively, and a test that needs
 * a real browser is a test that gets skipped when CI is slow. The convenient
 * one: the real transport is `--remote-debugging-pipe`, and a pipe is awkward
 * to stand up in a unit test.
 *
 * The production implementation speaks CDP over the pipe file descriptors
 * Chromium is launched with — deliberately not a WebSocket, because a
 * debugging *port* is reachable by anything on the machine, including the pages
 * being driven. The pipe is inherited by the bridge process alone.
 */
export type CdpMessage = {
  readonly id?: number;
  readonly method?: string;
  readonly sessionId?: string;
  readonly params?: Readonly<Record<string, unknown>>;
  readonly result?: unknown;
  readonly error?: { readonly code: number; readonly message: string };
};

export interface CdpTransport {
  /** Send a command upstream and resolve with Chromium's reply. */
  send(msg: CdpMessage): Promise<CdpMessage>;
  /** Register a listener for events pushed by Chromium. */
  onEvent(listener: (evt: CdpMessage) => void): void;
  close(): Promise<void>;
}

/** In-memory transport for tests: records what was sent, replays scripted events. */
export class FakeCdpTransport implements CdpTransport {
  readonly sent: CdpMessage[] = [];
  #listeners: ((evt: CdpMessage) => void)[] = [];
  closed = false;

  /** targetId → the session this fake handed out for it. */
  readonly sessions = new Map<string, string>();

  async send(msg: CdpMessage): Promise<CdpMessage> {
    this.sent.push(msg);
    const base = msg.id !== undefined ? { id: msg.id } : {};

    // Answer Target.attachToTarget the way Chromium does: with a sessionId.
    //
    // The fake used to reply `{ ok: true }` to everything, so nothing in the
    // suite ever went through the attach handshake, and both the proxy and the
    // fill engine could address pages by `params.targetId` — a dialect the
    // browser does not speak — with every test still green. A test double that
    // answers a protocol nobody implements verifies nothing about the protocol.
    // Chromium answers Target.createTarget with the new targetId.
    if (msg.method === "Target.createTarget") {
      const id = `target-${this.sent.filter((m) => m.method === "Target.createTarget").length}`;
      return { ...base, result: { targetId: id } };
    }

    if (msg.method === "Target.attachToTarget") {
      const target = typeof msg.params?.targetId === "string" ? msg.params.targetId : "unknown";
      const sessionId = `session-for-${target}`;
      this.sessions.set(target, sessionId);
      return { ...base, result: { sessionId } };
    }

    return { ...base, result: { ok: true } };
  }

  onEvent(listener: (evt: CdpMessage) => void): void {
    this.#listeners.push(listener);
  }

  /** Simulate Chromium pushing an event. */
  emit(evt: CdpMessage): void {
    for (const l of this.#listeners) l(evt);
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}
