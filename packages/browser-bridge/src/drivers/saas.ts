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
  /**
   * The caller the vault authenticates as: a user session token or `1ck_` key
   * for opening a session, the agent's own JWT for asking about a fill.
   *
   * Two credentials, not one. The vault refuses a session opened with an agent
   * token and refuses a fill that does not also name an agent, so a single
   * bearer could not satisfy both routes even if we wanted it to.
   */
  readonly userToken: string;
  readonly agentToken: string;
  /** The agent fills are requested for. Part of the path on both fill routes. */
  readonly agentId: string;
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
  /** Set by `openSession`; the vault requires both on the fill routes. */
  #session: { id: string; token: string } | undefined;

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
      // Off until the vault routes exist. A capability advertised ahead of its
      // endpoint registers a tool that fails on first call, which teaches an
      // agent to retry against a 404.
      checkout: false,
      signing: false,
      hitl: false,
      centralAudit: true,
      shadowReports: false,
    };
  }

  async openSession(ctx: SessionCtx): Promise<Session> {
    const res = await this.#post<{
      session_id: string;
      session_token: string;
      expires_at: string;
    }>(`/v1/agents/${encodeURIComponent(this.#opts.agentId)}/browser/sessions`, this.#opts.userToken, {
      agent_id: this.#opts.agentId,
      client_id: ctx.clientId,
      bridge_version: ctx.bridgeVersion,
      protocol_version: PROTOCOL_VERSION,
    });
    // The token is held in this process only — it is what proves a fill belongs
    // to a session this bridge opened, so it never reaches the core or an agent.
    // The id is what the request bodies name; they are different values and
    // sending one where the other belongs fails every fill.
    this.#session = { id: res.session_id, token: res.session_token };
    return { id: res.session_id, createdAt: new Date().toISOString(), expiresAt: res.expires_at };
  }

  async closeSession(_id: string): Promise<void> {
    // No route yet. Sessions expire server-side, so dropping the token here is
    // the whole of what this process can do; pretending otherwise by calling a
    // 404 would surface as an error on every clean shutdown.
    this.#session = undefined;
  }

  async authorizeFill(req: FillRequest): Promise<FillDecision> {
    const res = await this.#post<{
      kind: string;
      grant_id: string;
      binding_id: string;
      login_url: string;
      expires_at: string;
    }>(
      `/v1/agents/${encodeURIComponent(this.#opts.agentId)}/browser/fills`,
      // The agent's token: the vault requires the fill to name the agent it is
      // for, and refuses a bridge credential presented on its own.
      this.#opts.agentToken,
      {
        session_id: req.sessionId,
        binding_id: req.bindingId,
        tab_origin: req.tabOrigin,
        frame_origin: req.frameOrigin,
        form_action_origin: req.formActionOrigin,
        frame_id: req.frameId,
        generation: req.generation,
      },
    );
    return {
      kind: "grant",
      grantId: res.grant_id,
      bindingId: res.binding_id,
      loginUrl: res.login_url,
      expiresAt: res.expires_at,
      generation: req.generation,
    };
  }

  async consumeFill(grant: Grant): Promise<SecretHandle> {
    const res = await this.#raw(
      `/v1/agents/${encodeURIComponent(this.#opts.agentId)}/browser/fills/consume`,
      // The user's token, not the agent's. The vault refuses an agent principal
      // here: the agent asks which binding, the bridge collects the answer.
      this.#opts.userToken,
      {
        session_id: this.#openSessionId(),
        grant_id: grant.grantId,
        generation: grant.generation,
      },
    );
    // Read as bytes, never as a string: a string would be interned and live
    // until GC with no way to zero it.
    const bytes = new Uint8Array(await res.arrayBuffer());
    return SecretHandle.adopt(bytes, `binding:${grant.bindingId}`);
  }

  async audit(_event: AuditEvent): Promise<void> {
    // The vault writes its own hash-chained audit entry for every pair, session,
    // authorise and consume. A second, client-supplied record would be a log an
    // attacker on this machine controls, sitting beside one they do not.
  }

  async policySnapshot(): Promise<GuardrailSnapshot> {
    throw new Error("shadow reports are not available on this backend");
  }

  #openSessionId(): string {
    if (!this.#session) throw new Error("no open browser session");
    return this.#session.id;
  }

  async #raw(path: string, bearer: string, body: unknown): Promise<Response> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      authorization: `Bearer ${bearer}`,
      // The device credential. A separate header from the bearer because it
      // authenticates a different thing: the machine, not the principal.
      "x-1claw-bridge-credential": this.#opts.bridgeCredential,
      "x-1claw-bridge-version": this.#opts.bridgeVersion,
      "x-1claw-protocol-version": PROTOCOL_VERSION,
    };
    if (this.#session) headers["x-1claw-bridge-session"] = this.#session.token;

    const res = await this.#fetch(`${this.#opts.baseUrl}${path}`, {
      method: "POST",
      headers,
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

  async #post<T>(path: string, bearer: string, body: unknown): Promise<T> {
    return (await this.#raw(path, bearer, body)).json() as Promise<T>;
  }
}
