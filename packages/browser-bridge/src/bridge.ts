// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { randomBytes } from "node:crypto";

import { CdpGate } from "./cdp-policy.js";
import type { CdpMessage, CdpTransport } from "./cdp-transport.js";
import { FillEngine, type FillOutcome } from "./fill-engine.js";
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
    },
  ): Promise<ToolResult>;
  close(): Promise<void>;
};

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

  /** Set once the proxy exists; it learns the attachments clients make. */
  let proxyTargetForSession: ((sessionId: string) => string | undefined) | undefined;

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
    if (evt.method === "Target.attachedToTarget") {
      const p = evt.params as
        | { sessionId?: unknown; targetInfo?: { targetId?: unknown } }
        | undefined;
      if (typeof p?.sessionId === "string" && typeof p.targetInfo?.targetId === "string") {
        sessionTargets.set(p.sessionId, p.targetInfo.targetId);
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

  const fills = new FillEngine({
    backend,
    transport,
    gate,
    currentGeneration: (t) => generations.current(t),
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
    ...(opts.host !== undefined ? { host: opts.host } : {}),
    ...(opts.port !== undefined ? { port: opts.port } : {}),
  });

  // Now that the proxy exists, navigation events can fall back to the
  // attachments it learned from clients issuing Target.attachToTarget.
  proxyTargetForSession = (sid) => server.proxy.targetForSession(sid);

  const { host, port, url } = await server.listen();
  const sessionId = randomBytes(12).toString("hex");

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
      await server.close();
      await transport.close();
    },
  };
}
