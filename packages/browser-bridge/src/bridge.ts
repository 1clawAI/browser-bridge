// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { randomBytes } from "node:crypto";
import { PROTOCOL_VERSION } from "@1claw/browser-bridge-protocol";

import { CdpGate } from "./cdp-policy.js";
import type { CdpMessage, CdpTransport } from "./cdp-transport.js";
import { FillEngine, type FillOutcome } from "./fill-engine.js";
import { RegistrationEngine } from "./registration-engine.js";
import { buildToolset, dispatchTool, type ToolDefinition, type ToolResult } from "./mcp-tools.js";
import { PipeCdpTransport } from "./pipe-transport.js";
import { CdpProxyServer } from "./proxy-server.js";
import type { VaultBackend } from "./vault-backend.js";

/**
 * The whole bridge, assembled.
 *
 * Every part of this system was built and unit-tested in isolation and nothing
 * put them together: `FillEngine`, `CdpProxyServer` and `SaasDriver` were each
 * constructed only by their own tests. A library of correct parts is not a
 * working system, and the gap is where the interesting failures live — the fill
 * window that never fired did so because the proxy and the fill engine agreed
 * on a message shape the browser does not use, which no unit test could see.
 *
 * So this is the composition root, and it is deliberately the only place that
 * knows how the pieces fit:
 *
 *   Chromium ──pipe──▶ PipeCdpTransport ──▶ CdpProxy(CdpGate) ──▶ CdpProxyServer
 *                                │                                      ▲
 *                                │                                   agent
 *                                ▼
 *                          FillEngine ──▶ VaultBackend (SaasDriver)
 *
 * The agent talks to the proxy socket and never to Chromium. The fill engine
 * talks to Chromium directly, bypassing the gate, because the gate exists to
 * judge the agent and the bridge is the thing holding the window open.
 */

export type BridgeOptions = {
  /** Path to a Chromium binary. */
  readonly executablePath: string;
  /**
   * Where secrets and policy live.
   *
   * Supplied, never selected here. `core-has-no-driver-conditionals` fails the
   * build if this file so much as names a driver, and it caught the first
   * version of this function constructing a SaasDriver by default. That rule is
   * the reason the fill invariant is reviewable once instead of once per
   * backend, and a convenience default would have quietly forked it.
   */
  readonly backend: VaultBackend;
  readonly host?: string;
  readonly port?: number;
  readonly userDataDir?: string;
  /**
   * Extra Chromium flags, forwarded to the launch.
   *
   * This existed on the transport and not here, so a caller who passed
   * `--headless=new` to `startBridge` got a visible window and one who passed
   * `--no-sandbox` got a browser that exited immediately. Both are silent: the
   * option is simply gone. It cost a red CI run to find, because the desktop
   * where the tests were written is the one environment where dropping the
   * flags still works.
   */
  readonly args?: readonly string[];
  /** Injectable so the whole bridge can be driven by a fake in tests. */
  readonly transport?: CdpTransport;
};

export type BridgeHandle = {
  /** Where the agent points its CDP client. Carries the session token. */
  readonly url: string;
  readonly host: string;
  readonly port: number;
  /** The MCP tools this backend's capabilities allow. */
  readonly tools: readonly ToolDefinition[];
  /** Run one MCP tool call. */
  callTool(
    name: string,
    args: Readonly<Record<string, unknown>>,
    observe: () => {
      tabOrigin: string;
      frameOrigin: string;
      formActionOrigin: string;
      frameId: string;
      generation: number;
      /** Path of the form being filled, for the binding's fingerprint. */
      formPath: string;
      /** Field names on that form. A missing expected one means drift. */
      fieldNames: readonly string[];
      /** Hosts the login has redirected through, in order. Empty means none. */
      redirectChain: readonly string[];
      /** The generation *now*, compared against the one decided against. */
      currentGeneration: number;
    },
  ): Promise<ToolResult>;
  close(): Promise<void>;
};

/**
 * What this build reports to a backend.
 *
 * The hosted vault refuses bridges below a minimum, so this has to be a real
 * value rather than "unknown" — a version it cannot parse is turned away.
 */
const BRIDGE_VERSION = "0.1.0";

/**
 * Binds a backend's registration methods to the core's registration engine.
 *
 * The engine does not know which backend it is talking to — the same rule as
 * the fill path, and what `core-has-no-driver-conditionals` enforces.
 */
class RegistrationAdapter {
  readonly #engine: RegistrationEngine;
  readonly #backend: VaultBackend;

  constructor(
    backend: VaultBackend,
    transport: CdpTransport,
    gate: CdpGate,
    onError: (e: unknown) => void,
  ) {
    this.#backend = backend;
    const b = backend as unknown as {
      takeRegistrationSecret?: (id: string) => Promise<never>;
      commitRegistration?: (id: string) => Promise<{ bindingId: string }>;
      cancelRegistration?: (id: string) => Promise<void>;
    };
    this.#engine = new RegistrationEngine({
      transport,
      gate,
      // A backend advertising the capability without these is a programming
      // error, and one worth failing loudly on rather than half-registering.
      takeSecret: (id) => {
        if (!b.takeRegistrationSecret) {
          throw new Error("backend advertises registration but cannot produce a secret");
        }
        return b.takeRegistrationSecret(id);
      },
      commit: (id) => {
        if (!b.commitRegistration) {
          throw new Error("backend advertises registration but cannot commit");
        }
        return b.commitRegistration(id);
      },
      cancel: async (id) => {
        await b.cancelRegistration?.(id);
      },
      onError,
    });
  }

  async register(siteId: string): Promise<ToolResult> {
    const b = this.#backend as unknown as {
      beginRegistration?: (req: { siteId: string }) => Promise<Record<string, unknown>>;
    };
    if (!b.beginRegistration) return { status: "error", message: "registration is not available" };

    const decision = await b.beginRegistration({ siteId });
    if (decision.kind !== "registration_grant") {
      return { status: "denied", reason: String(decision.reason ?? "policy_denied") };
    }
    const outcome = await this.#engine.register(decision as never);
    switch (outcome.status) {
      case "registered":
        return { status: "registered", bindingId: outcome.bindingId };
      case "denied":
        return { status: "denied", reason: outcome.reason };
      case "rejected":
        return { status: "rejected", reason: outcome.reason };
      default:
        return { status: "error", message: outcome.message };
    }
  }
}

/** Bumped by navigation; the fill re-checks it immediately before typing. */
class Generations {
  readonly #byTarget = new Map<string, number>();

  bump(targetId: string): void {
    this.#byTarget.set(targetId, (this.#byTarget.get(targetId) ?? 0) + 1);
  }

  current(targetId: string): number {
    return this.#byTarget.get(targetId) ?? 0;
  }
}

export async function startBridge(opts: BridgeOptions): Promise<BridgeHandle> {
  const transport =
    opts.transport ??
    PipeCdpTransport.launch({
      executablePath: opts.executablePath,
      ...(opts.userDataDir !== undefined ? { userDataDir: opts.userDataDir } : {}),
      ...(opts.args !== undefined ? { args: opts.args } : {}),
    });

  const backend = opts.backend;

  const gate = new CdpGate();
  const generations = new Generations();

  // sessionId → targetId, learned from the browser's own attach announcements.
  //
  // Navigation events are addressed by session; the fill engine's TOCTOU check
  // is keyed by target. This listener used to bump the generation under
  // `evt.sessionId` while the engine read it under a targetId, so the two
  // counters never met: every navigation bumped a key nothing read, and a grant
  // survived the navigation it existed to be invalidated by.
  const sessionTargets = new Map<string, string>();
  /** targetId → browserContextId, so a fill lands in the agent's own context. */
  const targetContexts = new Map<string, string>();

  /** Set once the proxy exists; it learns the attachments clients make. */
  let proxyTargetForSession: ((sessionId: string) => string | undefined) | undefined;
  let proxyContextForTarget: ((targetId: string) => string | undefined) | undefined;

  const targetOfEvent = (evt: CdpMessage): string | undefined => {
    // The frame the event is about, when the browser names it.
    const frame = (evt.params as { frame?: { id?: unknown } } | undefined)?.frame;
    if (typeof frame?.id === "string") return frame.id;
    if (typeof evt.params?.targetId === "string") return evt.params.targetId as string;
    if (typeof evt.sessionId === "string") {
      return sessionTargets.get(evt.sessionId) ?? proxyTargetForSession?.(evt.sessionId);
    }
    return undefined;
  };

  // Navigation is what invalidates an authorisation, so the generation is
  // driven by the browser's own events rather than by anything the agent says.
  transport.onEvent((evt) => {
    if (evt.method === "Target.attachedToTarget" || evt.method === "Target.targetCreated") {
      const p = evt.params as
        | {
            sessionId?: unknown;
            targetInfo?: { targetId?: unknown; browserContextId?: unknown };
          }
        | undefined;
      const info = p?.targetInfo;
      if (typeof p?.sessionId === "string" && typeof info?.targetId === "string") {
        sessionTargets.set(p.sessionId, info.targetId);
      }
      // The context a target belongs to. Needed so a fill's throwaway page is
      // created in the *agent's* context: cookies belong to a context, not a
      // target, so a page opened in the default context logs in somewhere the
      // agent cannot reach. The fill engine has always asked for this and
      // nothing ever supplied it, which made the comment promising it
      // aspirational.
      if (typeof info?.targetId === "string" && typeof info.browserContextId === "string") {
        targetContexts.set(info.targetId, info.browserContextId);
      }
      return;
    }
    if (evt.method === "Target.detachedFromTarget") {
      const sid = (evt.params as { sessionId?: unknown } | undefined)?.sessionId;
      if (typeof sid === "string") sessionTargets.delete(sid);
      return;
    }
    if (evt.method === "Page.frameNavigated" || evt.method === "Page.navigatedWithinDocument") {
      const target = targetOfEvent(evt);
      if (target) generations.bump(target);
    }
  });

  // Only constructed when the backend says it can register.
  const registrations = backend.capabilities().registration
    ? new RegistrationAdapter(backend, transport, gate, (e) =>
        console.error("[browser-bridge] registration failed:", e),
      )
    : undefined;

  const fills = new FillEngine({
    backend,
    transport,
    gate,
    currentGeneration: (t) => generations.current(t),
    // Without this the fill's throwaway page is created in the default context
    // and the session cookie lands where the agent can never use it.
    // The proxy is authoritative: it placed the agent's target, so it knows the
    // context. The event-derived map is only a fallback for targets it did not
    // open, and needs setDiscoverTargets to be populated at all.
    browserContextOf: (t) => proxyContextForTarget?.(t) ?? targetContexts.get(t),
    // stderr, not the tool result. The operator needs the reason; the agent
    // must not have it.
    onError: (e) => console.error("[browser-bridge] fill failed:", e),
  });

  // A token in the URL path, minted per run. The socket is loopback-only and
  // origin-checked, but a token means a local process that guesses the port
  // still cannot drive the browser.
  const token = randomBytes(24).toString("base64url");

  const server = new CdpProxyServer({
    transport,
    token,
    // Give each client a *real* Chromium browser context.
    //
    // Without this the proxy fell back to `ctx-${clientId}` — a string Chromium
    // has never heard of. Two things followed. The per-client isolation this
    // package promises did not exist, because no context was ever created. And
    // event scoping compares Chromium's real browserContextId against the
    // client's, so context-scoped events matched nothing and were delivered to
    // nobody.
    createContext: async () => {
      const created = (await transport.send({ method: "Target.createBrowserContext" })) as {
        result?: { browserContextId?: string };
      };
      const id = created.result?.browserContextId;
      if (!id) throw new Error("Chromium would not create a browser context");
      return id;
    },
    ...(opts.host !== undefined ? { host: opts.host } : {}),
    ...(opts.port !== undefined ? { port: opts.port } : {}),
  });

  // Now that the proxy exists, navigation events can fall back to the
  // attachments it learned from clients issuing Target.attachToTarget.
  proxyTargetForSession = (sid) => server.proxy.targetForSession(sid);
  proxyContextForTarget = (t) => server.proxy.contextForTarget(t);

  const { host, port, url } = await server.listen();

  // Open a session on the backend, and use the id it returns.
  //
  // This used to be `randomBytes(12).toString("hex")` — an id the core invented
  // and no backend had ever heard of. `openSession` was declared on
  // `VaultBackend` and implemented by every driver, and nothing called it. The
  // saas driver therefore never held a session token, so `consumeFill` threw
  // "no open browser session"; the mock refuses every fill as `session_expired`.
  // The whole client path was broken for both, and stayed hidden because the
  // end-to-end tests drove the vault's HTTP API directly rather than going
  // through the bridge.
  //
  // If the backend cannot open a session, that is fatal here rather than at the
  // first fill: a bridge that has listened and printed a URL looks ready.
  const session = await backend.openSession({
    clientId: randomBytes(12).toString("hex"),
    bridgeVersion: BRIDGE_VERSION,
    protocolVersion: PROTOCOL_VERSION,
  });
  const sessionId = session.id;

  return {
    url,
    host,
    port,
    tools: buildToolset(backend.capabilities()),

    async callTool(name, args, observe) {
      return dispatchTool(name, args, {
        backend,
        sessionId,
        observe,
        // Present only when the backend advertises it. A tool the adapter does
        // not register cannot be called, so this is belt and braces — but a
        // capability can differ from a method's existence on a driver, and the
        // tool must not work in that gap.
        ...(registrations ? { register: (siteId: string) => registrations.register(siteId) } : {}),
        // The executor is the only path from a tool call to a credential, and
        // it returns a status. A tool result that carried the secret would be
        // the shortest way around every control in this package.
        execute: async (decision): Promise<ToolResult> => {
          // The decision carries the authorisation; the target and selector
          // come from the call. Deliberately not from the decision: the vault
          // decides *whether*, the agent says *where on the page*, and the
          // login URL comes from the binding rather than either of them.
          if (decision.kind !== "grant") {
            return decision.kind === "denied"
              ? { status: "denied", reason: decision.reason }
              : {
                  status: "awaiting_approval",
                  approvalId: decision.approvalId,
                  pollAfterMs: decision.pollAfterMs,
                };
          }

          const targetId = typeof args.target_id === "string" ? args.target_id : "";
          const selector = typeof args.selector === "string" ? args.selector : "";
          if (!targetId || !selector) {
            return { status: "error", message: "target_id and selector are required" };
          }

          const outcome: FillOutcome = await fills.fill(targetId, decision, selector);
          switch (outcome.status) {
            case "filled":
              return { status: "filled", bindingId: decision.bindingId };
            case "aborted":
              // The page moved between authorisation and typing. Its own
              // status, not an error: an agent that retries blindly on a stale
              // generation is asking for the credential to land on whatever
              // page arrived in the meantime, and `error` is the status most
              // likely to be retried.
              return { status: "aborted", reason: outcome.reason };
            default:
              return { status: "error", message: outcome.message };
          }
        },
      });
    },

    async close() {
      // Tell the backend before tearing the transport down, so a hosted vault
      // marks the session closed rather than waiting out its TTL.
      await backend.closeSession(sessionId).catch(() => {});
      await server.close();
      await transport.close();
    },
  };
}
