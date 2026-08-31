// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import {
  PROTOCOL_VERSION,
  type AuditEvent,
  type Capabilities,
  type FillDecision,
  type FillRequest,
  type Grant,
  type GuardrailSnapshot,
  type Session,
  type SessionCtx,
} from "@1claw/browser-bridge-protocol";
import { SecretHandle } from "../secret-handle.js";
import type { VaultBackend } from "../vault-backend.js";

export type SaasDriverOptions = {
  readonly baseUrl: string;
  /** The `bb_` bridge credential from `1claw browser-bridge login`. Never leaves this process. */
  readonly bridgeCredential: string;
  readonly bridgeVersion: string;
  readonly fetch?: typeof globalThis.fetch;
};

/**
 * The 1Claw-hosted backend: policy, audit and secrets all live in the vault.
 *
 * This driver is deliberately thin. It decides nothing about whether a fill is
 * safe — it asks the vault, and the core enforces the origin, frame, TOCTOU and
 * CDP rules regardless of what the vault says. A compromised or buggy driver
 * should not be able to widen the invariant, only to refuse.
 */
export class SaasDriver implements VaultBackend {
  readonly #opts: SaasDriverOptions;
  readonly #fetch: typeof globalThis.fetch;

  constructor(opts: SaasDriverOptions) {
    this.#opts = opts;
    this.#fetch = opts.fetch ?? globalThis.fetch;
  }

  capabilities(): Capabilities {
    return {
      fills: true,
      // v0.2. Off until the registration flow and its adversarial suite land;
      // the tool is absent rather than present-and-refusing.
      registration: false,
      checkout: true,
      signing: true,
      hitl: true,
      centralAudit: true,
      shadowReports: true,
    };
  }

  async openSession(ctx: SessionCtx): Promise<Session> {
    return this.#post<Session>("/v1/browser/sessions", {
      client_id: ctx.clientId,
      bridge_version: ctx.bridgeVersion,
      protocol_version: PROTOCOL_VERSION,
    });
  }

  async closeSession(id: string): Promise<void> {
    await this.#post(`/v1/browser/sessions/${encodeURIComponent(id)}/close`, {});
  }

  async authorizeFill(req: FillRequest): Promise<FillDecision> {
    return this.#post<FillDecision>("/v1/browser/fills/authorize", {
      session_id: req.sessionId,
      binding_id: req.bindingId,
      tab_origin: req.tabOrigin,
      frame_origin: req.frameOrigin,
      form_action_origin: req.formActionOrigin,
      generation: req.generation,
    });
  }

  async consumeFill(grant: Grant): Promise<SecretHandle> {
    const res = await this.#raw("/v1/browser/fills/consume", {
      grant_id: grant.grantId,
    });
    // Read as bytes, never as a string: a string would be interned and live
    // until GC with no way to zero it.
    const bytes = new Uint8Array(await res.arrayBuffer());
    return SecretHandle.adopt(bytes, `binding:${grant.bindingId}`);
  }

  async audit(event: AuditEvent): Promise<void> {
    await this.#post("/v1/browser/audit", event);
  }

  async policySnapshot(): Promise<GuardrailSnapshot> {
    return this.#post<GuardrailSnapshot>("/v1/browser/policy/snapshot", {});
  }

  async #raw(path: string, body: unknown): Promise<Response> {
    const res = await this.#fetch(`${this.#opts.baseUrl}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.#opts.bridgeCredential}`,
        "x-1claw-bridge-version": this.#opts.bridgeVersion,
        "x-1claw-protocol-version": PROTOCOL_VERSION,
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      // The body may name a binding but never carries secret material; still,
      // only the status and a bounded reason are surfaced.
      const reason = await res.text().catch(() => "");
      throw new Error(`browser bridge vault call failed (${res.status}): ${reason.slice(0, 200)}`);
    }
    return res;
  }

  async #post<T>(path: string, body: unknown): Promise<T> {
    return (await this.#raw(path, body)).json() as Promise<T>;
  }
}
