// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * A step-by-step record of what a fill, registration or capture actually did,
 * for the operator, never the agent. This is deliberately not in
 * `@1claw/browser-bridge-protocol`: that package's types cross the MCP
 * boundary to the agent, and a `TraceEvent` never does. It goes only to
 * whatever `onStep` callback the operator supplied to `startBridge`, the same
 * way `onError` and `onAudit` already work.
 *
 * Two things a `TraceEvent` is not, on purpose:
 *
 * - It is not `AuditEvent` (`@1claw/browser-bridge-protocol`). `AuditEvent` is
 *   a driver's own compliance record — coarse, string/number/boolean metadata
 *   only, meant for a backend's central log (the `centralAudit` capability,
 *   unimplemented by any driver yet). A `TraceEvent` is finer-grained (every
 *   step, not just the outcome), engine-level rather than driver-level, and
 *   can carry a screenshot. Building a debug/playback trace out of
 *   `AuditEvent` would have meant loosening its "no secret, no binary" shape
 *   for everyone; keeping them separate means neither has to compromise.
 * - It is never a substitute for the invariant. The screenshot, when present,
 *   is a real image of the real page — that is the point, an operator
 *   debugging a selector that never matched needs to see what the page
 *   actually looked like. A password field renders masked by the browser
 *   itself regardless of when the screenshot is taken, so this never shows
 *   one in the clear. An `extraFields` value (a date of birth, typed as plain
 *   text) is a different case: if the field is visible on the settled page,
 *   the screenshot shows it, the same way it would to a person looking at
 *   the screen. That is not a new exposure — the operator who authored the
 *   policy already has that value — but it means trace output deserves the
 *   same handling care as anything else carrying that data, which is the
 *   caller's responsibility once `onStep` hands it over.
 */
export type TraceEvent = {
  readonly op: "fill" | "registration" | "capture";
  /** bindingId, registrationId or entryId — whichever the operation has. */
  readonly id: string;
  /**
   * A short, stable name for what happened: "navigate", "wait_for_field",
   * "focus", "type_username", "type_extra_field", "type_secret", "submit",
   * "settle", "closed". New steps may be added over time; treat this as an
   * open set, not an enum to switch exhaustively on.
   */
  readonly step: string;
  readonly at: number;
  readonly ok: boolean;
  /**
   * A selector, a hostname, a failure reason — never a secret, and never an
   * `extraFields` value. Typed as a plain string rather than a closed set
   * because the detail is for a human reading a log, not for code to branch
   * on.
   */
  readonly detail?: string;
  /** A PNG of the page at a coarse checkpoint (after navigate, before close) — not every step. */
  readonly screenshotPng?: Uint8Array;
};
