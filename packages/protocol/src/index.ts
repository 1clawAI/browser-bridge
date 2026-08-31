// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * Wire types for the browser bridge.
 *
 * Published so a third party can implement the protocol without reading the
 * bridge, and so the closed Vault handlers and the open bridge cannot drift.
 * Nothing here may carry secret material: these types cross the MCP boundary,
 * and the invariant is that a secret never does. Secrets are handled only as
 * an opaque handle inside the bridge process.
 */

/** Semver of the bridge↔vault protocol. The vault refuses versions it knows to be vulnerable. */
export const PROTOCOL_VERSION = "0.1.0";

/**
 * What a backend can do.
 *
 * Read at startup by the tool adapter, which registers only the tools that are
 * backed by a real capability. A capability that is false must leave its tool
 * *absent* rather than present-and-failing: an agent that can see a tool will
 * try it, and a runtime upsell in agent-visible output is not acceptable.
 */
export type Capabilities = {
  /** Always true: filling a credential is the reason the bridge exists. */
  readonly fills: true;
  /** v0.2, and gated by backend *and* policy. */
  readonly registration: boolean;
  readonly checkout: boolean;
  readonly signing: boolean;
  /** Human-in-the-loop approvals are available and enforceable. */
  readonly hitl: boolean;
  readonly centralAudit: boolean;
  readonly shadowReports: boolean;
};

export type SessionCtx = {
  readonly clientId: string;
  /** Bridge build, so the vault can refuse known-vulnerable versions. */
  readonly bridgeVersion: string;
  readonly protocolVersion: string;
};

export type Session = {
  readonly id: string;
  readonly createdAt: string;
  readonly expiresAt: string;
};

/**
 * A request to fill one credential into one field.
 *
 * `tabOrigin` and `frameOrigin` are separate because a cross-origin iframe is
 * the classic way to read a fill that looks like it landed on the right site.
 * They are compared by the core, not by a driver.
 */
export type FillRequest = {
  readonly sessionId: string;
  readonly bindingId: string;
  readonly tabOrigin: string;
  readonly frameOrigin: string;
  /** Origin the form will POST to, resolved from the live DOM at request time. */
  readonly formActionOrigin: string;
  /** Monotonic per-target counter; invalidated by navigation. See TOCTOU handling. */
  readonly generation: number;
};

export type Grant = {
  readonly kind: "grant";
  readonly grantId: string;
  readonly bindingId: string;
  /** The bridge must navigate here itself rather than trusting an agent-supplied URL. */
  readonly loginUrl: string;
  readonly expiresAt: string;
  readonly generation: number;
};

export type Denied = {
  readonly kind: "denied";
  readonly reason: DenyReason;
  readonly message: string;
};

export type AwaitingApproval = {
  readonly kind: "awaiting_approval";
  readonly approvalId: string;
  readonly pollAfterMs: number;
};

export type FillDecision = Grant | Denied | AwaitingApproval;

/**
 * Why a fill was refused. A closed set, because these reach agent-visible
 * output and an agent that can see free text will try to talk its way around
 * it. The bridge never explains *which* credential exists.
 */
export type DenyReason =
  | "origin_not_allowed"
  | "frame_origin_mismatch"
  | "form_action_not_allowed"
  | "redirect_chain_not_allowed"
  | "form_fingerprint_drift"
  | "generation_stale"
  | "velocity_exceeded"
  | "capability_unavailable"
  | "policy_denied"
  | "session_expired"
  | "fill_in_progress";

export type AuditEvent = {
  readonly type: string;
  readonly sessionId: string;
  readonly bindingId?: string;
  readonly at: string;
  /** Must never contain secret material; the core asserts this before dispatch. */
  readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
};

export type GuardrailSnapshot = {
  readonly policyHash: string;
  readonly capturedAt: string;
  readonly allowedHosts: readonly string[];
  readonly ssoHosts: readonly string[];
};
