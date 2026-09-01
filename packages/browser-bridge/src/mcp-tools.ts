// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import type { Capabilities, FillDecision } from "@1claw/browser-bridge-protocol";
import { toolsFor, type VaultBackend } from "./vault-backend.js";

/**
 * The tools an agent can actually call.
 *
 * Two rules shape this surface, and both are about what an agent is *not*
 * given rather than what it is:
 *
 *   - **Status only.** `request_fill` asks the bridge to type a credential; it
 *     does not return one. The agent learns whether the fill happened, never
 *     what was typed. There is deliberately no tool that returns credential
 *     material, because a tool that could would be the shortest path around
 *     every other control in this repository.
 *   - **Absent, not disabled.** A tool whose capability is off is not
 *     registered at all. A tool that exists and always fails teaches an agent
 *     to retry, and puts a runtime upsell into agent-visible output.
 *
 * Deny reasons come from the closed set in the protocol. Free text would reach
 * an agent that will happily try to argue with it, and it risks naming which
 * credential exists.
 */

export type ToolDefinition = {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Readonly<Record<string, unknown>>;
};

export type ToolResult =
  | { readonly status: "filled"; readonly bindingId: string }
  | { readonly status: "denied"; readonly reason: string }
  | { readonly status: "awaiting_approval"; readonly approvalId: string; readonly pollAfterMs: number }
  | { readonly status: "in_progress"; readonly bindingId: string }
  /**
   * The page moved between authorisation and typing, so nothing was typed.
   *
   * Its own status rather than an `error`, because the two call for opposite
   * responses: an error is worth retrying, and a stale generation retried
   * blindly is how a credential lands on whatever page arrived in the meantime.
   */
  | { readonly status: "aborted"; readonly reason: string }
  | { readonly status: "error"; readonly message: string };

const SCHEMAS: Record<string, Readonly<Record<string, unknown>>> = {
  request_fill: {
    type: "object",
    properties: {
      binding_id: { type: "string", description: "Which stored credential to type." },
      // Deliberately no url, username, password or field value. The bridge
      // navigates to the binding's own login_url; an agent-supplied URL would
      // let the agent choose the page that receives the credential.
    },
    required: ["binding_id"],
    additionalProperties: false,
  },
  get_fill_status: {
    type: "object",
    properties: { binding_id: { type: "string" } },
    required: ["binding_id"],
    additionalProperties: false,
  },
};

const DESCRIPTIONS: Record<string, string> = {
  request_fill:
    "Ask 1Claw to type a stored credential into the current login form. Returns only whether it happened — never the credential.",
  get_fill_status: "Check whether a requested fill has completed.",
  request_checkout: "Request a capped, just-in-time card for a checkout flow.",
  request_signature: "Request a signature from a vault-held key.",
  get_approval_status: "Check whether a human has approved a pending request.",
  get_shadow_report: "Read what policy would have done, without enforcing it.",
  begin_credential_registration: "Begin a governed account registration.",
  get_registration_status: "Check a registration in progress.",
  cancel_registration: "Cancel a registration in progress.",
};

/** Tool definitions for a backend, in a stable order. */
export function buildToolset(capabilities: Capabilities): ToolDefinition[] {
  return toolsFor(capabilities).map((name) => ({
    name,
    description: DESCRIPTIONS[name] ?? name,
    inputSchema: SCHEMAS[name] ?? { type: "object", properties: {}, additionalProperties: false },
  }));
}

export type FillExecutor = (decision: FillDecision) => Promise<ToolResult>;

/**
 * Handle one tool call.
 *
 * `execute` is the bridge's fill engine — it consumes the grant and types,
 * inside this process. It is passed in rather than reached for so that this
 * layer cannot be handed a secret to return by mistake: its own return type has
 * no shape that could carry one.
 */
export async function dispatchTool(
  name: string,
  args: Readonly<Record<string, unknown>>,
  ctx: {
    readonly backend: VaultBackend;
    readonly sessionId: string;
    readonly execute: FillExecutor;
    readonly observe: () => {
      tabOrigin: string;
      frameOrigin: string;
      formActionOrigin: string;
      frameId: string;
      generation: number;
    };
  },
): Promise<ToolResult> {
  const available = new Set(toolsFor(ctx.backend.capabilities()));
  if (!available.has(name)) {
    // Same answer for "does not exist" and "not enabled for this backend":
    // the difference is a fact about the customer's plan, not the agent's.
    return { status: "error", message: `unknown tool: ${name}` };
  }

  const bindingId = typeof args.binding_id === "string" ? args.binding_id : "";
  if (!bindingId) return { status: "error", message: "binding_id is required" };

  switch (name) {
    case "request_fill": {
      // Page state is read by the bridge, not accepted from the agent: an agent
      // that supplies the origin gets to choose which page looks trustworthy.
      const observed = ctx.observe();
      const decision = await ctx.backend.authorizeFill({
        sessionId: ctx.sessionId,
        bindingId,
        ...observed,
      });
      if (decision.kind === "denied") return { status: "denied", reason: decision.reason };
      if (decision.kind === "awaiting_approval") {
        return {
          status: "awaiting_approval",
          approvalId: decision.approvalId,
          pollAfterMs: decision.pollAfterMs,
        };
      }
      return ctx.execute(decision);
    }

    case "get_fill_status":
      return { status: "in_progress", bindingId };

    default:
      return { status: "error", message: `tool ${name} is not implemented in this build` };
  }
}
