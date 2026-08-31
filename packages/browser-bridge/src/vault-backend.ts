// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import type {
  AuditEvent,
  Capabilities,
  FillDecision,
  FillRequest,
  GuardrailSnapshot,
  Grant,
  Session,
  SessionCtx,
} from "@1claw/browser-bridge-protocol";
import type { SecretHandle } from "./secret-handle.js";

/**
 * What a backend must provide, and the only thing the core is allowed to know
 * about where secrets live.
 *
 * Drivers own four things and no others: where secrets live, who evaluates
 * policy, where audit goes, and which capabilities exist. Everything that
 * makes a fill *safe* — origin and frame checks, TOCTOU generation binding,
 * the CDP fill window, buffer zeroing, velocity limiting — belongs to the core
 * and behaves identically on every backend. That split is what makes the
 * security invariant reviewable once instead of once per driver, and it is why
 * `core-has-no-driver-conditionals.test.ts` fails the build if the core ever
 * branches on which driver it is talking to.
 *
 * The optional members are capability-gated. A backend that returns
 * `checkout: false` must not implement `authorizeCheckout`, and the adapter
 * must not register the tool: an agent that can see a tool will call it.
 */
export interface VaultBackend {
  /** Read once at startup. Drives which tools get registered at all. */
  capabilities(): Capabilities;

  openSession(ctx: SessionCtx): Promise<Session>;
  closeSession(id: string): Promise<void>;

  /**
   * Decide whether this fill may happen. Returns a grant, a refusal, or a
   * pending human approval — never a secret.
   */
  authorizeFill(req: FillRequest): Promise<FillDecision>;

  /**
   * Exchange a grant for the secret itself.
   *
   * Returns a handle rather than a string so that the value cannot be
   * serialised into a tool result, logged, or embedded in an error. Callers
   * should use `handle.use(...)` so the buffer is zeroed even when the fill
   * throws.
   */
  consumeFill(grant: Grant): Promise<SecretHandle>;

  audit(event: AuditEvent): Promise<void>;
  policySnapshot(): Promise<GuardrailSnapshot>;

  // ── Capability-gated (v0.2+) ────────────────────────────────────────────
  beginRegistration?(req: unknown): Promise<unknown>;
  commitRegistration?(grant: unknown): Promise<unknown>;
  cancelRegistration?(id: string): Promise<void>;
  authorizeCheckout?(req: unknown): Promise<unknown>;
  authorizeSignature?(req: unknown): Promise<unknown>;
}

/**
 * Names of the tools each capability unlocks.
 *
 * Kept beside the trait so that adding a capability without deciding what it
 * exposes is a type error rather than an oversight.
 */
export const CAPABILITY_TOOLS: Readonly<Record<keyof Capabilities, readonly string[]>> = {
  fills: ["request_fill", "get_fill_status"],
  registration: ["begin_credential_registration", "get_registration_status", "cancel_registration"],
  checkout: ["request_checkout"],
  signing: ["request_signature"],
  hitl: ["get_approval_status"],
  centralAudit: [],
  shadowReports: ["get_shadow_report"],
} as const;

/**
 * The tools an adapter should register for a backend.
 *
 * Absent, not disabled: a tool that exists and always fails teaches an agent to
 * retry, and puts an upsell in agent-visible output.
 */
export function toolsFor(capabilities: Capabilities): string[] {
  const out: string[] = [];
  for (const [capability, tools] of Object.entries(CAPABILITY_TOOLS)) {
    if (capabilities[capability as keyof Capabilities]) out.push(...tools);
  }
  return out.sort();
}
