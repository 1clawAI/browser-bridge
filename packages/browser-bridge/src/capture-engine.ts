// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import type { CaptureGrant, CaptureOutcome } from "@1claw/browser-bridge-protocol";
import type { CdpGate } from "./cdp-policy.js";
import type { CdpTransport } from "./cdp-transport.js";
import { SecretHandle } from "./secret-handle.js";

export type CaptureEngineDeps = {
  readonly transport: CdpTransport;
  readonly gate: CdpGate;
  /**
   * The browser context the agent's target lives in.
   *
   * A capture reads a secret the site shows only to a logged-in session, and
   * that session lives in the agent's context (a fill put it there). So the
   * windowed page is opened in that same context — authenticated — rather than
   * a fresh one, exactly as a fill's typing page is.
   */
  readonly browserContextOf?: (targetId: string) => string | undefined;
  /** Store the captured secret. Consumes the handle. Returns the vault id. */
  readonly commit: (captureId: string, secret: SecretHandle) => Promise<{ entryId: string }>;
  readonly cancel: (captureId: string) => Promise<void>;
  readonly onError?: (error: unknown) => void;
  /** How long to wait for the value to appear before giving up. */
  readonly settleMs?: number;
};

const DEFAULT_SETTLE_MS = 15_000;
const POLL_MS = 250;

/**
 * Read a secret a site generates, and store it — without the agent seeing it.
 *
 * The mirror image of the fill engine, and it earns the same invariant the same
 * way. The value is read in a target the agent has never scripted, while the
 * agent's own target is windowed so it cannot observe the read, and the value
 * is wrapped in a `SecretHandle` the instant it exists and handed to the
 * backend — it never becomes a tool result, a log line, or a return value.
 *
 * The ordering matters, as it does for a fill:
 *
 *   1. Window the agent's target first, before any secret exists here — a gap
 *      before the window is a gap in which a listener the agent installed
 *      earlier could watch the read.
 *   2. Open the read page in the agent's own context, so it is logged in.
 *   3. Generate (if the policy names a control), then read the value.
 *   4. Wrap and commit; the buffer is zeroed by the handle.
 *   5. Close the window in `finally`, so a failure cannot strand it.
 */
export class CaptureEngine {
  readonly #deps: CaptureEngineDeps;

  constructor(deps: CaptureEngineDeps) {
    this.#deps = deps;
  }

  async capture(agentTargetId: string, grant: CaptureGrant): Promise<CaptureOutcome> {
    const { transport, gate, commit, cancel } = this.#deps;
    const settleMs = this.#deps.settleMs ?? DEFAULT_SETTLE_MS;

    // 1. Block the agent's own target before anything is read.
    gate.openFillWindow(agentTargetId);

    let target: string | undefined;
    let handle: SecretHandle | undefined;
    let committed = false;
    try {
      // 2. A page the agent has never scripted, in the agent's context so the
      //    site's logged-in session applies.
      const contextId = this.#deps.browserContextOf?.(agentTargetId);
      const created = (await transport.send({
        method: "Target.createTarget",
        params: { url: "about:blank", ...(contextId !== undefined ? { browserContextId: contextId } : {}) },
      })) as { result?: { targetId?: string } };
      target = created.result?.targetId;
      if (!target) return { status: "error", message: "could not open a page" };

      // Window it immediately: getTargets and attachToTarget are allowlisted, so
      // an agent that notices the new target must still be refused on it.
      gate.openFillWindow(target);

      const attached = (await transport.send({
        method: "Target.attachToTarget",
        params: { targetId: target, flatten: true },
      })) as { result?: { sessionId?: string } };
      const sessionId = attached.result?.sessionId;
      if (!sessionId) return { status: "error", message: "could not attach" };

      await transport.send({ sessionId, method: "Page.enable" });
      await transport.send({ sessionId, method: "Runtime.enable" });
      // The policy's URL, never the agent's.
      await transport.send({ sessionId, method: "Page.navigate", params: { url: grant.captureUrl } });

      // 3. Generate, if there is a control to click, then read.
      if (grant.source.generateSelector) {
        await this.#waitFor(sessionId, grant.source.generateSelector, settleMs);
        await this.#click(sessionId, grant.source.generateSelector);
      }
      const value = await this.#readValue(sessionId, grant.source, settleMs);
      if (value === undefined || value === "") {
        await cancel(grant.captureId);
        return { status: "rejected", reason: "no_value_found" };
      }

      // 4. Own the bytes before anything else touches them, then commit.
      handle = SecretHandle.adopt(new TextEncoder().encode(value), `capture:${grant.entryId}`);
      const { entryId } = await commit(grant.captureId, handle);
      // commit consumed the handle; drop the reference so `finally` does not
      // dispose an inert one.
      handle = undefined;
      committed = true;
      return { status: "captured", entryId };
    } catch (err) {
      // Not `err.message`: this reaches the agent, and the text comes from the
      // transport and the backend.
      this.#deps.onError?.(err);
      return { status: "error", message: "the capture did not complete" };
    } finally {
      handle?.dispose();
      if (!committed) await cancel(grant.captureId).catch(() => {});
      if (target !== undefined) {
        await this.#deps.transport
          .send({ method: "Target.closeTarget", params: { targetId: target } })
          .catch(() => {});
        this.#deps.gate.closeFillWindow(target);
      }
      // 5. Always. A stuck window locks the agent out of its own browser.
      this.#deps.gate.closeFillWindow(agentTargetId);
    }
  }

  /** Poll the value selector until it holds something, or time out. */
  async #readValue(
    sessionId: string,
    source: CaptureGrant["source"],
    settleMs: number,
  ): Promise<string | undefined> {
    const sel = JSON.stringify(source.valueSelector);
    const read = source.valueAttr
      ? `document.querySelector(${sel})?.getAttribute(${JSON.stringify(source.valueAttr)}) ?? ""`
      : source.valueProp === "value"
        ? `document.querySelector(${sel})?.value ?? ""`
        : source.valueProp === "textContent"
          ? `(document.querySelector(${sel})?.textContent ?? "").trim()`
          : // Take whichever is non-empty: an input exposes .value, a code block
            // exposes .textContent, and reading the wrong one yields "".
            `(el => el ? String(el.value || (el.textContent || "").trim()) : "")(document.querySelector(${sel}))`;
    const deadline = Date.now() + settleMs;
    while (Date.now() < deadline) {
      const v = await this.#eval(sessionId, read);
      if (typeof v === "string" && v !== "") return v;
      await new Promise((r) => setTimeout(r, POLL_MS));
    }
    return undefined;
  }

  async #waitFor(sessionId: string, selector: string, timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await this.#present(sessionId, selector)) return;
      await new Promise((r) => setTimeout(r, POLL_MS));
    }
    throw new Error(`the control never appeared (${selector})`);
  }

  async #present(sessionId: string, selector: string): Promise<boolean> {
    return (await this.#eval(sessionId, `!!document.querySelector(${JSON.stringify(selector)})`)) === true;
  }

  async #click(sessionId: string, selector: string): Promise<void> {
    await this.#eval(sessionId, `document.querySelector(${JSON.stringify(selector)})?.click()`);
  }

  async #eval(sessionId: string, expression: string): Promise<unknown> {
    const out = (await this.#deps.transport.send({
      sessionId,
      method: "Runtime.evaluate",
      params: { expression, returnByValue: true },
    })) as { result?: { result?: { value?: unknown } } };
    return out.result?.result?.value;
  }
}
