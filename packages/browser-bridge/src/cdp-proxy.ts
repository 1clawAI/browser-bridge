// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { CdpGate, redactEventForAgent, type CdpDecision } from "./cdp-policy.js";
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
  /** Clients that asked for target discovery, answered locally. */
  readonly #discovering = new Set<ClientId>();
  /** Clients that asked to auto-attach, answered locally. */
  readonly #autoAttaching = new Set<ClientId>();
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
    this.#discovering.delete(clientId);
    this.#autoAttaching.delete(clientId);
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

    // Answer the framework attach handshake here rather than forwarding it.
    //
    // Puppeteer and Playwright open a connection by asking the browser to
    // describe itself and to start announcing targets. Forwarded, those
    // commands would put Chromium into a mode where it reports *every* target
    // to whoever asked — including other clients' pages — which is why
    // setAutoAttach and setDiscoverTargets are in NEVER_ALLOWED and must stay
    // there. Answered locally, the client gets the handshake it needs and a
    // view containing only its own targets.
    //
    // Nothing synthesised here names a target the client does not own; that is
    // the property the tests hold, because a discovery reply that leaked one
    // would be a way back to an ungated page.
    const handled = await this.#answerHandshake(clientId, msg);
    if (handled) return handled;

    // Refuse anything naming a target or session the client does not own.
    //
    // This is the command-side half of the confinement. Event delivery was
    // already filtered per client, which made the gap read as closed, but
    // Target.getTargets, getTargetInfo and attachToTarget are all allowlisted
    // and none of them checked whose target was named. So B could list A's
    // pages, attach to one, and drive it with the sessionId Chromium returned:
    // Runtime.evaluate on A's page, Network.getCookies for A's session. The
    // class doc names that outcome as the thing it prevents — agent B simply
    // logged in as A — and until now only events were stopping it.
    //
    // Ownership was already being recorded on every attach and read only by
    // the event filter. Nothing new has to be tracked; it has to be consulted.
    const confined = this.#refuseIfNotOwned(clientId, msg);
    if (confined) return confined;

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
        const url = typeof msg.params?.url === "string" ? msg.params.url : "";
        const targetInfo = {
          targetId: created,
          type: "page",
          title: "",
          url,
          attached: false,
          browserContextId: ctx,
        };

        // Tell this client — and only this client — that its page exists. A
        // framework that asked for discovery is waiting for exactly this before
        // it will consider the page usable.
        if (this.#discovering.has(clientId)) {
          this.#sinks.get(clientId)?.({
            method: "Target.targetCreated",
            params: { targetInfo },
          });
        }

        // Attach on the client's behalf, and tell it.
        //
        // A client that asked for auto-attach does not attach to its own pages;
        // it waits to be told it has been attached, and builds its Page object
        // out of the sessionId in that event. Puppeteer's newPage() hangs
        // forever without it — thirty seconds of a test timing out with no
        // error, which is what the first version of this answerer did.
        //
        // The attach is real, not synthesised: Chromium issues the session, so
        // the sessionId in the event is one that works, and it is recorded as
        // this client's so the ownership check lets it be used. Faking an id
        // here would produce a client that believes it has a page and is
        // refused on every command it sends to it.
        if (this.#autoAttaching.has(clientId)) {
          const attached = await this.#transport.send({
            method: "Target.attachToTarget",
            params: { targetId: created, flatten: true },
          });
          const sessionId = (attached.result as { sessionId?: unknown } | undefined)?.sessionId;
          if (typeof sessionId === "string") {
            // Recorded, not announced. Chromium emits its own
            // Target.attachedToTarget for a real attach, and the event filter
            // delivers it to whoever owns the session — which is why the
            // ownership has to be recorded first. Emitting one here as well
            // gave the client two, and two attach events for one target build
            // two Page objects, of which only one is listening for the replies.
            this.#sessionTargets.set(sessionId, created);
            this.#sessionOwners.set(sessionId, clientId);
          }
        }
      }
    }
    if (msg.method === "Target.closeTarget") {
      const closed = msg.params?.targetId;
      if (typeof closed === "string" && this.#targetContexts.get(closed) === this.#contexts.get(clientId)) {
        this.#targetContexts.delete(closed);
        if (this.#discovering.has(clientId)) {
          this.#sinks.get(clientId)?.({
            method: "Target.targetDestroyed",
            params: { targetId: closed },
          });
        }
      }
    }
    this.#learnSession(clientId, msg, result);

    // Chromium answers getTargets with every target it has, including other
    // clients' pages and their URLs. Refusing the command outright would break
    // the frameworks that call it on connect, so the reply is narrowed to what
    // the caller owns instead — same list it would see if it were alone.
    if (msg.method === "Target.getTargets") {
      return { kind: "forward", message: this.#onlyOwnTargets(clientId, result) };
    }

    return { kind: "forward", message: result };
  }

  /**
   * The ownership check every command passes through.
   *
   * A message names a target one of two ways: a `sessionId` from a previous
   * attach, or `params.targetId`. Both are checked against what this client
   * owns — sessions against the attach ledger, targets against the browser
   * context the bridge put them in.
   *
   * Unknown ids are refused rather than allowed. A target the proxy has no
   * record of is one it did not create for anybody, and letting those through
   * would reopen the hole for any id an agent can guess or read from an event.
   */
  #refuseIfNotOwned(clientId: ClientId, msg: CdpMessage): ProxyReply | undefined {
    if (typeof msg.sessionId === "string") {
      const owner = this.#sessionOwners.get(msg.sessionId);
      if (owner !== clientId) {
        return this.#refuse(msg, "session belongs to another client");
      }
    }

    const named = msg.params?.targetId;
    if (typeof named === "string") {
      const ctx = this.#contexts.get(clientId);
      if (ctx === undefined || this.#targetContexts.get(named) !== ctx) {
        return this.#refuse(msg, "target belongs to another client");
      }
    }

    return undefined;
  }

  /**
   * Strip the credential-bearing fields from an event forwarded for its shape.
   *
   * The two Network ExtraInfo events are delivered so a stock client's network
   * bookkeeping can settle a navigation, and stripped so the agent never sees
   * the `Cookie` and `Set-Cookie` headers that ride along with them.
   */
  #redacted(evt: CdpMessage): CdpMessage {
    if (!evt.method) return evt;
    const params = redactEventForAgent(evt.method, evt.params);
    return params === evt.params ? evt : { ...evt, ...(params !== undefined ? { params } : {}) };
  }

  /** Narrow a Target.getTargets reply to the caller's own context. */
  #onlyOwnTargets(clientId: ClientId, reply: CdpMessage): CdpMessage {
    const ctx = this.#contexts.get(clientId);
    const infos = (reply.result as { targetInfos?: unknown } | undefined)?.targetInfos;
    if (!Array.isArray(infos)) return reply;

    const mine = infos.filter((t) => {
      const id = (t as { targetId?: unknown }).targetId;
      return typeof id === "string" && ctx !== undefined && this.#targetContexts.get(id) === ctx;
    });

    return { ...reply, result: { ...(reply.result as object), targetInfos: mine } };
  }

  /**
   * Which target is this message about?
   *
   * A session id resolves through the attach map; `params.targetId` is still
   * honoured for the session-less commands that genuinely carry it
   * (Target.closeTarget, Target.attachToTarget itself). Checking both is what
   * makes the fill window cover the methods that can read the field.
   */
  /**
   * Reply to the commands a stock CDP client sends on connect.
   *
   * Returns a reply when it handled the command, or undefined to let it
   * continue to the gate and the browser.
   */
  async #answerHandshake(clientId: ClientId, msg: CdpMessage): Promise<ProxyReply | undefined> {
    const id = msg.id;
    // Echo the sessionId. A reply to a session-scoped command carries the
    // session it belongs to, and a client routes it by that: Playwright asserts
    // when a reply arrives on the root session with an id the root never sent,
    // which is what every locally-answered command looked like. Puppeteer
    // tolerated it, so only one of the two clients showed the bug.
    const ok = (result: Record<string, unknown>): ProxyReply => ({
      kind: "forward",
      message: {
        ...(id !== undefined ? { id } : {}),
        ...(typeof msg.sessionId === "string" ? { sessionId: msg.sessionId } : {}),
        result,
      },
    });

    switch (msg.method) {
      case "Browser.getVersion": {
        // Forwarded, because it is honest and leaks nothing: version strings
        // only. Browser.getBrowserCommandLine, which *would* leak (flags
        // include --user-data-dir), stays refused.
        const real = await this.#transport.send({ method: "Browser.getVersion" });
        return ok((real.result as Record<string, unknown>) ?? {});
      }

      case "Target.setDiscoverTargets": {
        // Accepted, not forwarded. The client is told about its own targets
        // and nothing else; Chromium is never put into global discovery.
        this.#discovering.add(clientId);
        const reply = ok({});
        if (msg.params?.discover === true) {
          // Announce what it already has, as Chromium would on enabling
          // discovery, so a client that connects after opening a page is not
          // left believing the browser is empty.
          for (const [targetId, ctx] of this.#targetContexts) {
            if (ctx !== this.#contexts.get(clientId)) continue;
            this.#sinks.get(clientId)?.({
              method: "Target.targetCreated",
              params: {
                targetInfo: {
                  targetId,
                  type: "page",
                  title: "",
                  url: "",
                  attached: false,
                  browserContextId: ctx,
                },
              },
            });
          }
        }
        return reply;
      }

      case "Target.getBrowserContexts":
        // Puppeteer's very next call after getVersion. Chromium would answer
        // with every context in the browser — one line per other client — so it
        // is answered here with the caller's own and nothing else.
        return ok({ browserContextIds: [this.#contexts.get(clientId)].filter(Boolean) });

      case "Browser.setDownloadBehavior":
        // Playwright sends this on connect. Accepted and not forwarded: the
        // parameters name a download directory and a behaviour, and forwarding
        // them lets any client redirect the whole browser's downloads to a path
        // it chooses. Downloads are not part of what the bridge offers, so
        // there is nothing to do and nothing to pass on.
        return ok({});

      case "Runtime.runIfWaitingForDebugger":
        // Nothing is ever waiting. Puppeteer asks for auto-attach with
        // `waitForDebuggerOnStart`, and that request is answered here and never
        // forwarded, so Chromium never pauses a target on creation and there is
        // no debugger to release. Refusing it made Puppeteer's own reply
        // handling fail on a command whose work was already done.
        return ok({});

      case "Target.setAutoAttach":
        // Accepted and remembered. Forwarding would have Chromium attach the
        // browser-level session to targets as they appear, handing the client
        // sessions it never asked for — including, eventually, ones in another
        // client's context.
        if (msg.params?.autoAttach === true) this.#autoAttaching.add(clientId);
        else this.#autoAttaching.delete(clientId);
        return ok({});

      default:
        return undefined;
    }
  }

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
      this.#sinks.get(owner)?.(this.#redacted(evt));
      return;
    }

    // Browser-level events may name the context they concern; deliver only to
    // clients confined to it.
    //
    // Target.* events carry it under `targetInfo`, not at the top level, so
    // reading only the top level let every target event fall past this and into
    // the global broadcast below — the opposite of confinement, and the reason
    // a client could have seen another client's pages appear.
    const info = evt.params?.targetInfo as { browserContextId?: unknown } | undefined;
    const ctx =
      typeof evt.params?.browserContextId === "string"
        ? evt.params.browserContextId
        : typeof info?.browserContextId === "string"
          ? info.browserContextId
          : undefined;
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
