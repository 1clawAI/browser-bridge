// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import type { RegistrationGrant, RegistrationOutcome } from "@1claw/browser-bridge-protocol";
import type { CdpGate } from "./cdp-policy.js";
import type { CdpTransport } from "./cdp-transport.js";
import type { SecretHandle } from "./secret-handle.js";

export type RegistrationEngineDeps = {
  readonly transport: CdpTransport;
  readonly gate: CdpGate;
  /** Fetches the generated password. Same contract as consuming a fill grant. */
  readonly takeSecret: (registrationId: string) => Promise<SecretHandle>;
  /** Writes the credential. Called only after the site has accepted it. */
  readonly commit: (registrationId: string) => Promise<{ bindingId: string }>;
  readonly cancel: (registrationId: string) => Promise<void>;
  readonly onError?: (error: unknown) => void;
  /** How long to wait for a success or error signal. */
  readonly settleMs?: number;
};

const DEFAULT_SETTLE_MS = 15_000;
const POLL_MS = 250;

/**
 * Create one account, in a page the agent has never scripted.
 *
 * The shape mirrors the fill engine, and for the same reasons: a throwaway
 * target so nothing the agent installed earlier can observe the typing, the CDP
 * window held open across it, and the window closed in `finally` so a failure
 * cannot lock the agent out of its own browser.
 *
 * The part that is not like a fill is deciding whether it worked. A fill either
 * typed or it did not; a registration has to know whether the *site* accepted
 * what was typed, and getting that wrong writes a password the site never
 * stored. So the check is explicit, human-authored, and defaults to refusing:
 * with no success signal the registration is cancelled, not committed.
 */
export class RegistrationEngine {
  readonly #deps: RegistrationEngineDeps;

  constructor(deps: RegistrationEngineDeps) {
    this.#deps = deps;
  }

  async register(grant: RegistrationGrant): Promise<RegistrationOutcome> {
    const { transport, gate, takeSecret, commit, cancel } = this.#deps;
    const settleMs = this.#deps.settleMs ?? DEFAULT_SETTLE_MS;

    let target: string | undefined;
    let handle: SecretHandle | undefined;
    let committed = false;

    try {
      const created = (await transport.send({
        method: "Target.createTarget",
        params: { url: "about:blank" },
      })) as { result?: { targetId?: string } };
      target = created.result?.targetId;
      if (!target) return { status: "error", message: "could not open a page" };

      // Windowed immediately: Target.getTargets and attachToTarget are both
      // allowlisted, so an agent that notices this page must still be refused
      // on it.
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
      await transport.send({
        sessionId,
        method: "Page.navigate",
        params: { url: grant.signupUrl },
      });
      await this.#waitFor(sessionId, grant.usernameSelector, settleMs);

      const before = await this.#url(sessionId);

      await this.#type(sessionId, grant.usernameSelector, grant.username);
      handle = await takeSecret(grant.registrationId);
      // `use()` inside typeSecret has already zeroed the buffer; dropping the
      // reference stops `finally` from disposing an inert handle again.
      await this.#typeSecret(sessionId, grant.passwordSelector, handle);
      handle = undefined;

      if (grant.submitSelector) {
        await this.#click(sessionId, grant.submitSelector);
      } else {
        await this.#eval(sessionId, `document.querySelector(${JSON.stringify(grant.passwordSelector)})?.form?.submit()`);
      }

      const verdict = await this.#settle(sessionId, grant, before, settleMs);
      if (verdict === "rejected") {
        await cancel(grant.registrationId);
        return { status: "rejected", reason: "site_rejected_password" };
      }
      if (verdict === "unknown") {
        // The default, and deliberately so. A registration we cannot confirm is
        // not committed: a stored password the site never accepted is worse
        // than a retry, because it fails silently much later.
        await cancel(grant.registrationId);
        return { status: "rejected", reason: "no_success_signal" };
      }

      const { bindingId } = await commit(grant.registrationId);
      committed = true;
      return { status: "registered", bindingId };
    } catch (err) {
      // Not `err.message`: this reaches the agent, and the text comes from the
      // transport and the backend.
      this.#deps.onError?.(err);
      return { status: "error", message: "the registration did not complete" };
    } finally {
      handle?.dispose();
      if (!committed) await cancel(grant.registrationId).catch(() => {});
      if (target !== undefined) {
        await this.#deps.transport
          .send({ method: "Target.closeTarget", params: { targetId: target } })
          .catch(() => {});
        this.#deps.gate.closeFillWindow(target);
      }
    }
  }

  /** Error signal first: a page can show both an error and a success marker. */
  async #settle(
    sessionId: string,
    grant: RegistrationGrant,
    urlBefore: string,
    settleMs: number,
  ): Promise<"ok" | "rejected" | "unknown"> {
    const deadline = Date.now() + settleMs;
    while (Date.now() < deadline) {
      if (grant.success.errorSelector && (await this.#present(sessionId, grant.success.errorSelector))) {
        return "rejected";
      }
      if (grant.success.selector && (await this.#present(sessionId, grant.success.selector))) {
        return "ok";
      }
      if (grant.success.urlChanges) {
        const now = await this.#url(sessionId);
        if (now && now !== urlBefore) return "ok";
      }
      await new Promise((r) => setTimeout(r, POLL_MS));
    }
    return "unknown";
  }

  async #waitFor(sessionId: string, selector: string, timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await this.#present(sessionId, selector)) return;
      await new Promise((r) => setTimeout(r, POLL_MS));
    }
    throw new Error(`the signup form never appeared (${selector})`);
  }

  async #present(sessionId: string, selector: string): Promise<boolean> {
    const out = await this.#eval(sessionId, `!!document.querySelector(${JSON.stringify(selector)})`);
    return out === true;
  }

  async #url(sessionId: string): Promise<string> {
    const out = await this.#eval(sessionId, "location.href");
    return typeof out === "string" ? out : "";
  }

  async #type(sessionId: string, selector: string, value: string): Promise<void> {
    await this.#eval(sessionId, `document.querySelector(${JSON.stringify(selector)})?.focus()`);
    await this.#deps.transport.send({ sessionId, method: "Input.insertText", params: { text: value } });
  }

  /** Types from the handle, so the value is never a variable in this scope. */
  async #typeSecret(sessionId: string, selector: string, handle: SecretHandle): Promise<void> {
    await this.#eval(sessionId, `document.querySelector(${JSON.stringify(selector)})?.focus()`);
    const text = handle.use((bytes) => new TextDecoder().decode(bytes));
    await this.#deps.transport.send({ sessionId, method: "Input.insertText", params: { text } });
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
