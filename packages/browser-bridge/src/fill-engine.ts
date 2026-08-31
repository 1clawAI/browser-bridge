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
    try {
      // 2. The binding's URL, not the agent's.
      await this.#send({ method: "Page.navigate", params: { targetId, url: grant.loginUrl } });

      // 3. Navigation bumps the generation, so this catches both a page that
      //    moved on its own and one the agent moved underneath us.
      if (currentGeneration(targetId) !== grant.generation) {
        return { status: "aborted", reason: "generation_stale" };
      }

      handle = await backend.consumeFill(grant);

      // Focus first: typing into whatever happens to hold focus is how a
      // password ends up in a search box, or in the page's chat widget.
      await this.#send({
        method: "DOM.querySelector",
        params: { targetId, selector },
      });

      // Re-check after every await that could have yielded to a navigation.
      if (currentGeneration(targetId) !== grant.generation) {
        return { status: "aborted", reason: "navigated" };
      }

      // 4. Borrow, type, and let `use` zero the buffer even if this throws.
      const text = handle.use((bytes) => new TextDecoder().decode(bytes));
      await this.#send({ method: "Input.insertText", params: { targetId, text } });

      return { status: "filled" };
    } catch (e) {
      return { status: "error", message: e instanceof Error ? e.message : String(e) };
    } finally {
      // A handle that was consumed but never typed — because the generation
      // moved, or the transport threw — is still live until this runs.
      handle?.dispose();
      // 5. Always. A stuck window locks the agent out of its own browser.
      gate.closeFillWindow(targetId);
    }
  }

  /** Bridge-originated commands bypass the gate: the gate is for the agent. */
  async #send(msg: CdpMessage): Promise<CdpMessage> {
    return this.#deps.transport.send(msg);
  }
}
