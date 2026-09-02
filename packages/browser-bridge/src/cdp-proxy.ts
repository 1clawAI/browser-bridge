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
  /**
   * sessionId → targetId, learned from `Target.attachToTarget` replies.
   *
   * CDP addresses an attached page by a **top-level `sessionId`**, not by
   * `params.targetId`. Runtime.evaluate, Runtime.callFunctionOn, DOM.getDocument,
   * DOM.querySelector, Input.dispatchKeyEvent, Input.insertText and
   * Accessibility.getFullAXTree — every command that can read a form field —
   * carry no `params.targetId` at all.
   *
   * Reading only `params.targetId` therefore left `targetId` undefined for
   * exactly the methods the fill window exists to stop: the `&&` short-circuited
   * and the block never ran. Target.attachToTarget is itself allowlisted, so
   * obtaining a session was a permitted first step.
   */
  readonly #sessionTargets = new Map<string, string>();
  /**
   * targetId → the browser context it lives in.
   *
   * Recorded when the proxy places a target, so a fill can open its throwaway
   * page in the *same* context: cookies belong to a context, not a page, and a
   * session that lands in the default context is one the agent can never use.
   */
  readonly #targetContexts = new Map<string, string>();
  /**
   * sessionId → the client that attached it.
   *
   * Event delivery was `for (const [, sink] of this.#sinks) sink(evt)` — an
   * unconditional broadcast that discarded the clientId one line before it would
   * have been used. Every client saw every other client's Page.*, Network.*,
   * DOM.* and Target.* events, which with Network.getCookies on the allowlist is
   * the "agent B is simply logged in as agent A" outcome this class's own doc
   * names as the thing not to lose.
   */
  readonly #sessionOwners = new Map<string, ClientId>();

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
    // Otherwise a later client could inherit a departed client's sessions.
    for (const [session, owner] of this.#sessionOwners) {
      if (owner === clientId) {
        this.#sessionOwners.delete(session);
        this.#sessionTargets.delete(session);
      }
    }
  }

  contextOf(clientId: ClientId): string | undefined {
    return this.#contexts.get(clientId);
  }

  /**
   * The target a CDP session is attached to, if this proxy saw the attach.
   *
   * Navigation events are addressed by session; the fill engine's TOCTOU check
   * is keyed by target. Without this translation the two never meet, and a
   * grant survives a navigation it was supposed to be invalidated by.
   */
  targetForSession(sessionId: string): string | undefined {
    return this.#sessionTargets.get(sessionId);
  }

  /** The browser context a target was opened in, if this proxy opened it. */
  contextForTarget(targetId: string): string | undefined {
    return this.#targetContexts.get(targetId);
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

    const targetId = this.#targetOf(msg);
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

    // A target the agent opens belongs in the agent's context.
    //
    // Chromium puts it in the default context otherwise, which quietly undoes
    // the confinement: two clients would share cookies, and the fill's session
    // would land somewhere its own agent cannot reach. The agent cannot choose
    // a context itself — Target.createBrowserContext is refused — so filling it
    // in here is the only way it is ever right.
    const outbound =
      msg.method === "Target.createTarget" && this.#contexts.has(clientId)
        ? {
            ...msg,
            params: {
              ...(msg.params ?? {}),
              browserContextId: this.#contexts.get(clientId),
            },
          }
        : msg;

    // Strip the agent's id before forwarding, and put it back on the reply.
    //
    // The transport reuses an incoming id when one is present, so an agent's
    // `id: 1` collided with the bridge's own internal id 1 — the reply was
    // matched to whichever pending entry got there first. The visible symptom
    // was Target.getTargets hanging forever on a fresh connection. The
    // invisible one is worse: two clients both counting from 1 would receive
    // each other's replies, which is exactly the confinement this class exists
    // to keep.
    const { id: clientMessageId, ...withoutId } = outbound;
    const forwarded = await this.#transport.send(withoutId);
    const result: CdpMessage =
      clientMessageId !== undefined ? { ...forwarded, id: clientMessageId } : forwarded;
    // Remember which context this target went into. We know it exactly — we put
    // it there — so there is no need to infer it from Target.targetCreated
    // events, which only arrive if setDiscoverTargets is on, and it is not.
    if (msg.method === "Target.createTarget") {
      const created = (result.result as { targetId?: unknown } | undefined)?.targetId;
      const ctx = this.#contexts.get(clientId);
      if (typeof created === "string" && ctx !== undefined) {
        this.#targetContexts.set(created, ctx);
      }
    }
    this.#learnSession(clientId, msg, result);
    return { kind: "forward", message: result };
  }

  /**
   * Which target is this message about?
   *
   * A session id resolves through the attach map; `params.targetId` is still
   * honoured for the session-less commands that genuinely carry it
   * (Target.closeTarget, Target.attachToTarget itself). Checking both is what
   * makes the fill window cover the methods that can read the field.
   */
  #targetOf(msg: CdpMessage): string | undefined {
    if (typeof msg.sessionId === "string") {
      const mapped = this.#sessionTargets.get(msg.sessionId);
      if (mapped !== undefined) return mapped;
      // An unknown session is not a free pass. Returning the session id itself
      // keeps it distinct from "no target", so a fill window opened on a target
      // we could not map still fails closed rather than matching nothing.
      return msg.sessionId;
    }
    return typeof msg.params?.targetId === "string" ? msg.params.targetId : undefined;
  }

  /** Record the session Chromium just handed out, so later commands resolve. */
  #learnSession(clientId: ClientId, sent: CdpMessage, reply: CdpMessage): void {
    if (sent.method !== "Target.attachToTarget") return;
    const target = typeof sent.params?.targetId === "string" ? sent.params.targetId : undefined;
    const result = reply.result as { sessionId?: unknown } | undefined;
    const session = typeof result?.sessionId === "string" ? result.sessionId : undefined;
    if (session === undefined) return;
    if (target !== undefined) this.#sessionTargets.set(session, target);
    this.#sessionOwners.set(session, clientId);
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
    // Same resolution as commands: events from an attached session carry
    // sessionId at the top level, so reading only params.targetId made
    // per-target suppression inert and left only the global never-forward list.
    const targetId = this.#targetOf(evt);
    const forwardable = this.#gate.shouldForwardEvent({
      method: evt.method,
      ...(targetId !== undefined ? { targetId } : {}),
      ...(evt.params !== undefined ? { params: evt.params } : {}),
    });
    if (!forwardable) return;

    // Deliver to the client the session belongs to, not to everyone.
    //
    // An event carrying a session we never saw attached is dropped rather than
    // broadcast: it belongs to somebody, and guessing wrong is exactly the leak.
    // Dropped here and now — nothing buffers, so there is nothing to replay.
    if (typeof evt.sessionId === "string") {
      const owner = this.#sessionOwners.get(evt.sessionId);
      if (owner === undefined) return;
      this.#sinks.get(owner)?.(evt);
      return;
    }

    // Browser-level events may name the context they concern; deliver only to
    // clients confined to it.
    const ctx =
      typeof evt.params?.browserContextId === "string" ? evt.params.browserContextId : undefined;
    if (ctx !== undefined) {
      for (const [clientId, sink] of this.#sinks) {
        if (this.#contexts.get(clientId) === ctx) sink(evt);
      }
      return;
    }

    // Genuinely global (browser lifecycle). No context to discriminate on.
    for (const [, sink] of this.#sinks) sink(evt);
  }

  async close(): Promise<void> {
    this.#sinks.clear();
    this.#contexts.clear();
    await this.#transport.close();
  }
}
