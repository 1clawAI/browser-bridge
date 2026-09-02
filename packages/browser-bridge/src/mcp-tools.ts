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
  /** An account now exists and its credential is in the vault. Never a password. */
  | { readonly status: "registered"; readonly bindingId: string }
  /** A site-generated secret was read and stored in the vault. Never the secret. */
  | { readonly status: "captured"; readonly entryId: string }
  /** The site did not accept it, or did not say so. Nothing was stored. */
  | { readonly status: "rejected"; readonly reason: string }
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
  begin_credential_registration: {
    type: "object",
    properties: {
      site_id: {
        type: "string",
        description:
          "Which pre-authorised site to create an account on. Deliberately the only input: the host, signup URL, username and form selectors all come from a policy a human wrote. An agent that could name the host would be choosing where a credential gets created.",
      },
    },
    required: ["site_id"],
    // No url, username, password or host. There is nothing here an agent could
    // set to redirect where the credential ends up.
    additionalProperties: false,
  },
  begin_credential_capture: {
    type: "object",
    properties: {
      site_id: {
        type: "string",
        description:
          "Which pre-authorised site to capture a secret from. The only input that names a policy: the URL, the control that generates the value, and where it is read from all come from a policy a human wrote. An agent that could name the source would be choosing what gets stored.",
      },
      target_id: {
        type: "string",
        description:
          "The tab the agent is logged in on. A capture reads a secret the site shows only to a logged-in session, so it runs in this tab's browser context; the agent is blocked from observing the read.",
      },
    },
    required: ["site_id", "target_id"],
    additionalProperties: false,
  },
  get_registration_status: {
    type: "object",
    properties: { binding_id: { type: "string" } },
    required: ["binding_id"],
    additionalProperties: false,
  },
  cancel_registration: {
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
  begin_credential_capture:
    "Capture a secret the site generates (an API key, a token) into the vault. Returns only whether it happened — never the secret.",
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
    /** Present only when the backend advertises `registration`. */
    readonly register?: (siteId: string) => Promise<ToolResult>;
    /** Present only when the backend advertises `capture`. */
    readonly capture?: (siteId: string, targetId: string) => Promise<ToolResult>;
    readonly observe: () => {
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
  // Registration and capture are identified by site, not a binding — a
  // registration has none yet, and a capture creates one — so both are exempt.
  if (
    !bindingId &&
    name !== "begin_credential_registration" &&
    name !== "begin_credential_capture"
  ) {
    return { status: "error", message: "binding_id is required" };
  }

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

    case "begin_credential_registration": {
      // The agent names a pre-authorised site and nothing else. No host, no
      // URL, no username — those come from a policy a human wrote, because a
      // registration has no binding yet, and whoever picks the host decides
      // where a credential gets created.
      if (!ctx.register) {
        return { status: "error", message: "registration is not available on this backend" };
      }
      const siteId = typeof args.site_id === "string" ? args.site_id : "";
      if (!siteId) return { status: "error", message: "site_id is required" };
      return ctx.register(siteId);
    }

    case "begin_credential_capture": {
      // Like registration, the agent names a pre-authorised site. It also names
      // the tab it is logged in on, because a capture reads a secret behind that
      // login — but it chooses nothing about what is read or where it is stored.
      if (!ctx.capture) {
        return { status: "error", message: "capture is not available on this backend" };
      }
      const siteId = typeof args.site_id === "string" ? args.site_id : "";
      const targetId = typeof args.target_id === "string" ? args.target_id : "";
      if (!siteId) return { status: "error", message: "site_id is required" };
      if (!targetId) return { status: "error", message: "target_id is required" };
      return ctx.capture(siteId, targetId);
    }

    case "get_registration_status":
    case "cancel_registration":
      return { status: "in_progress", bindingId };

    case "get_fill_status":
      return { status: "in_progress", bindingId };

    default:
      return { status: "error", message: `tool ${name} is not implemented in this build` };
  }
}
