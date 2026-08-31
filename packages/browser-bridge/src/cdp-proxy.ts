// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { CdpGate, type CdpDecision } from "./cdp-policy.js";
import type { CdpMessage, CdpTransport } from "./cdp-transport.js";

/**
 * The only way a framework reaches Chromium.
 *
 * Every agent command arrives here, is judged by the gate, and is either
 * forwarded upstream or answered with a refusal that never touches the browser.
 * Events travel the other way and are filtered before delivery.
 *
 * Two properties are worth stating because they are easy to lose in a refactor:
 *
 *   - a refused command is **not** sent upstream. Refusing after the fact would
 *     mean Chromium had already executed it, and for `Runtime.evaluate` the
 *     side effect *is* the exfiltration — the response filter would be closing
 *     the door behind the horse.
 *   - each client gets its own `BrowserContext`. Sharing one means agent B
 *     inherits agent A's session cookies, which is a policy bypass that leaks
 *     no secret and is therefore easy to miss: B is simply logged in as A.
 */

/** CDP error codes; -32601 is "method not found", which is what a blocked method looks like. */
const METHOD_NOT_FOUND = -32601;

export type ProxyReply =
  | { readonly kind: "forward"; readonly message: CdpMessage }
  | { readonly kind: "refuse"; readonly message: CdpMessage };

export type ClientId = string;

export class CdpProxy {
  readonly #transport: CdpTransport;
  readonly #gate: CdpGate;
  /** clientId → the BrowserContext it is confined to. */
  readonly #contexts = new Map<ClientId, string>();
  /** clientId → sink for events destined for that client. */
  readonly #sinks = new Map<ClientId, (evt: CdpMessage) => void>();

  constructor(transport: CdpTransport, gate: CdpGate = new CdpGate()) {
    this.#transport = transport;
    this.#gate = gate;
    this.#transport.onEvent((evt) => this.#fanOutEvent(evt));
  }

  get gate(): CdpGate {
    return this.#gate;
  }

  /** Attach a client and confine it to its own browser context. */
  register(clientId: ClientId, browserContextId: string, sink: (evt: CdpMessage) => void): void {
    this.#contexts.set(clientId, browserContextId);
    this.#sinks.set(clientId, sink);
  }

  unregister(clientId: ClientId): void {
    this.#contexts.delete(clientId);
    this.#sinks.delete(clientId);
  }

  contextOf(clientId: ClientId): string | undefined {
    return this.#contexts.get(clientId);
  }

  /**
   * Handle one command from a client.
   *
   * Returns the reply to send back. A refusal is shaped as an ordinary CDP
   * error so frameworks handle it on the path they already have, rather than
   * seeing a dropped connection and retrying.
   */
  async handleCommand(clientId: ClientId, msg: CdpMessage): Promise<ProxyReply> {
    if (!this.#contexts.has(clientId)) {
      return this.#refuse(msg, "client is not registered with the bridge");
    }
    if (!msg.method) {
      return this.#refuse(msg, "malformed command: no method");
    }

    const targetId = typeof msg.params?.targetId === "string" ? msg.params.targetId : undefined;
    const decision: CdpDecision = this.#gate.evaluateCommand({
      method: msg.method,
      ...(targetId !== undefined ? { targetId } : {}),
      ...(msg.params !== undefined ? { params: msg.params } : {}),
    });

    if (!decision.allow) {
      // Not forwarded. For Runtime.evaluate the side effect is the
      // exfiltration, so "execute then filter the response" is not a defence.
      return this.#refuse(msg, `${decision.reason}: ${decision.message}`);
    }

    const result = await this.#transport.send(msg);
    return { kind: "forward", message: result };
  }

  #refuse(msg: CdpMessage, message: string): ProxyReply {
    return {
      kind: "refuse",
      message: {
        ...(msg.id !== undefined ? { id: msg.id } : {}),
        error: { code: METHOD_NOT_FOUND, message },
      },
    };
  }

  /**
   * Deliver an event to the clients allowed to see it.
   *
   * Filtered per client, because a fill window belongs to a target and clients
   * work in different contexts. Suppressed events are dropped here and now;
   * nothing buffers them, so there is nothing to replay when the window closes.
   */
  #fanOutEvent(evt: CdpMessage): void {
    if (!evt.method) return;
    const targetId = typeof evt.params?.targetId === "string" ? evt.params.targetId : undefined;
    const forwardable = this.#gate.shouldForwardEvent({
      method: evt.method,
      ...(targetId !== undefined ? { targetId } : {}),
      ...(evt.params !== undefined ? { params: evt.params } : {}),
    });
    if (!forwardable) return;

    for (const [, sink] of this.#sinks) sink(evt);
  }

  async close(): Promise<void> {
    this.#sinks.clear();
    this.#contexts.clear();
    await this.#transport.close();
  }
}
