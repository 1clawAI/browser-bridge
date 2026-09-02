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
  /**
   * Capture a secret a site generates (an API key, a token) into the vault,
   * without the agent seeing it. Gated by backend *and* policy, like
   * registration.
   */
  readonly capture: boolean;
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
  /** The target the fill is for. Recorded on the grant, so a grant is redeemable
   *  only for the frame it was decided about. */
  readonly frameId: string;
  /** Monotonic per-target counter; invalidated by navigation. See TOCTOU handling. */
  readonly generation: number;
  /**
   * Path of the form being filled, matched against the binding's fingerprint.
   *
   * This and the three below were absent from the protocol while the vault
   * accepted them as optional, so no client ever sent them and the vault
   * defaulted them: the redirect-chain check ran over an empty list, the
   * generation check compared a value to itself, and `form_path` defaulted to
   * "" — which matches no fingerprint pattern, so every fingerprinted binding
   * was denied. Two checks silently off and one feature that could not work.
   * They are required here because the vault now requires them.
   */
  readonly formPath: string;
  /** Field names present on that form. A missing expected one means drift. */
  readonly fieldNames: readonly string[];
  /** Hosts the login has redirected through, in order. Empty means none. */
  readonly redirectChain: readonly string[];
  /** The target's generation as the bridge sees it *now*, to compare against
   *  `generation` — which is the one the agent's request was decided against. */
  readonly currentGeneration: number;
};

export type Grant = {
  readonly kind: "grant";
  readonly grantId: string;
  readonly bindingId: string;
  /** The bridge must navigate here itself rather than trusting an agent-supplied URL. */
  readonly loginUrl: string;
  readonly expiresAt: string;
  readonly generation: number;
  /**
   * A username to type before the password, for login forms that do not
   * pre-fill it. Not a secret — but typed by the bridge in the windowed page,
   * not by the agent, so the agent still never scripts the login. Both must be
   * present for the username to be typed.
   */
  readonly username?: string;
  readonly usernameSelector?: string;
  /**
   * A specific submit button to click, for forms that need the button's own
   * click rather than a bare form submit (an ASP.NET postback, a JS handler
   * bound to the button). Omit to submit generically.
   */
  readonly submitSelector?: string;
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

/**
 * A request to create an account.
 *
 * Deliberately thin. The agent names *which* pre-authorised site, and nothing
 * else — not the host, not the URL, not the username. In a fill the binding
 * already exists because a human made it; in a registration there is no binding
 * yet, so if the agent supplied the host it would be choosing where a credential
 * gets created. That inverts the trust model the rest of this package rests on.
 */
export type RegistrationRequest = {
  readonly siteId: string;
};

/**
 * Permission to attempt one registration.
 *
 * Carries no password. The generated secret is fetched separately as a
 * `SecretHandle`, for the same reason a fill grant carries none: an object the
 * agent could be handed must have no shape that could hold one.
 */
export type RegistrationGrant = {
  readonly kind: "registration_grant";
  readonly registrationId: string;
  /** From the policy, never from the agent. */
  readonly signupUrl: string;
  /** From the policy, never from the agent. */
  readonly username: string;
  /** Selectors on the signup form, as recorded by whoever wrote the policy. */
  readonly usernameSelector: string;
  readonly passwordSelector: string;
  readonly submitSelector?: string;
  /** How the bridge decides the site accepted the password. */
  readonly success: RegistrationSuccess;
};

/**
 * What counts as "the site accepted it".
 *
 * Explicit and human-authored rather than inferred. Committing a password a
 * site rejected produces a binding that will never work, and the failure
 * surfaces weeks later as a fill that cannot log in — so guessing here is worse
 * than requiring someone to say what success looks like.
 */
export type RegistrationSuccess = {
  /** The signup page navigating away is the default signal. */
  readonly urlChanges?: boolean;
  /** A selector that appears only once the account exists. */
  readonly selector?: string;
  /** A selector whose presence means the attempt failed. Checked first. */
  readonly errorSelector?: string;
};

export type RegistrationDecision = RegistrationGrant | Denied;

/** What the agent gets back. An id, never a credential. */
export type RegistrationOutcome =
  | { readonly status: "registered"; readonly bindingId: string }
  | { readonly status: "denied"; readonly reason: DenyReason }
  | { readonly status: "rejected"; readonly reason: "site_rejected_password" | "no_success_signal" }
  | { readonly status: "error"; readonly message: string };

/**
 * A request to capture a secret the site generates — an API key, an access
 * token — and store it in the vault, without the agent ever seeing it.
 *
 * The mirror image of a fill: a fill types a stored secret *into* a page; a
 * capture reads a site-generated secret *out* of a page and into the vault. It
 * carries the same invariant. Like a registration, the agent names only a
 * pre-authorised site. It does not choose the URL, the control that generates
 * the value, or where the value is read from — a human authored those, because
 * whatever is read off the page becomes a stored credential, and an agent that
 * chose the source would be choosing what gets stored.
 */
export type CaptureRequest = {
  readonly siteId: string;
};

/** How the bridge produces and then reads the value, all human-authored. */
export type CaptureSource = {
  /** A control the bridge clicks to make the secret appear. Omit if it is already shown. */
  readonly generateSelector?: string;
  /** Where the value is read from once it exists. */
  readonly valueSelector: string;
  /**
   * Read the element's `.value` (an input) or `.textContent` (a code block).
   * Omit to take whichever is non-empty.
   */
  readonly valueProp?: "value" | "textContent";
  /**
   * Read a named attribute instead — for a copy button that carries the secret
   * in `data-clipboard-text`, say, next to a label the textContent would drag
   * in. Wins over `valueProp` when set.
   */
  readonly valueAttr?: string;
};

/**
 * Permission to capture one secret.
 *
 * Carries no secret — the value does not exist when this is issued, and when it
 * does the bridge reads it in a windowed page and hands it straight to the
 * backend, never back through an object the agent could be given.
 */
export type CaptureGrant = {
  readonly kind: "capture_grant";
  readonly captureId: string;
  /** From the policy, never the agent. */
  readonly captureUrl: string;
  readonly source: CaptureSource;
  /** The vault id the captured secret is written under. */
  readonly entryId: string;
};

export type CaptureDecision = CaptureGrant | Denied;

/** What the agent gets back. An id, never the captured secret. */
export type CaptureOutcome =
  | { readonly status: "captured"; readonly entryId: string }
  | { readonly status: "denied"; readonly reason: DenyReason }
  | { readonly status: "rejected"; readonly reason: "no_value_found" }
  | { readonly status: "error"; readonly message: string };

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
