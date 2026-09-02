// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { randomUUID } from "node:crypto";
import type {
  AuditEvent,
  Capabilities,
  FillDecision,
  FillRequest,
  Grant,
  GuardrailSnapshot,
  Session,
  SessionCtx,
} from "@1claw/browser-bridge-protocol";
import { SecretHandle } from "../secret-handle.js";
import type { VaultBackend } from "../vault-backend.js";

/** A credential this mock will hand out, and the rules it is bound by. */
export type MockBinding = {
  readonly id: string;
  /** The value typed into the page. In memory only; never written anywhere. */
  readonly secret: string;
  /** The bridge navigates here itself rather than trusting an agent's URL. */
  readonly loginUrl: string;
  /** Bare entry matches only itself; a leading dot matches subdomains. */
  readonly allowedHosts: readonly string[];
  readonly ssoHosts?: readonly string[];
};

export type MockVaultDriverOptions = {
  readonly bindings: readonly MockBinding[];
  /** Fills per binding before refusal. Matches the hosted default. */
  readonly velocityLimit?: number;
  /** Seconds a grant stays redeemable. Matches the hosted default. */
  readonly grantTtlSeconds?: number;
  /** Called for each audit event, so a demo can show what was recorded. */
  readonly onAudit?: (event: AuditEvent) => void;
};

const DEFAULT_VELOCITY_LIMIT = 5;
const DEFAULT_GRANT_TTL_SECONDS = 60;

/**
 * An in-memory backend, so the bridge can be run without a 1Claw account.
 *
 * This exists because the only other driver talks to a hosted API. Someone
 * reading this repository could see the code and run the unit tests, and could
 * not watch the thing actually work — which is a poor way to present a package
 * whose entire claim is "the agent never sees the password". With this they can
 * run it, drive it, and try to break it.
 *
 * It is a real driver, not a stub: it decides *whether* a fill may proceed and
 * hands back a single-use grant, exactly as the hosted one does. What it does
 * not do is decide whether a fill is *safe* — origin and frame checks, the
 * TOCTOU generation binding, the CDP fill window and buffer zeroing all belong
 * to the core and behave identically here. A driver may refuse a fill; it can
 * never widen what is allowed. That is what makes this a fair demonstration
 * rather than a friendlier set of rules.
 *
 * **Not for production.** Secrets are held as plain strings in this process,
 * there is no authentication, and nothing is persisted or audited beyond the
 * callback. The hosted driver exists for the case where any of that matters.
 */
export class MockVaultDriver implements VaultBackend {
  readonly #bindings: Map<string, MockBinding>;
  readonly #velocityLimit: number;
  readonly #grantTtlMs: number;
  readonly #onAudit: ((event: AuditEvent) => void) | undefined;

  /** grantId → what it authorised. Deleted on redemption: single use. */
  readonly #grants = new Map<
    string,
    { bindingId: string; generation: number; expiresAt: number }
  >();
  /** bindingId → issue timestamps, for the velocity window. */
  readonly #issued = new Map<string, number[]>();
  #session: Session | undefined;

  constructor(opts: MockVaultDriverOptions) {
    this.#bindings = new Map(opts.bindings.map((b) => [b.id, b]));
    this.#velocityLimit = opts.velocityLimit ?? DEFAULT_VELOCITY_LIMIT;
    this.#grantTtlMs = (opts.grantTtlSeconds ?? DEFAULT_GRANT_TTL_SECONDS) * 1000;
    this.#onAudit = opts.onAudit;
  }

  capabilities(): Capabilities {
    return {
      fills: true,
      // Everything else is absent rather than present-and-refusing. A tool that
      // exists and always fails teaches an agent to retry.
      registration: false,
      checkout: false,
      signing: false,
      hitl: false,
      centralAudit: false,
      shadowReports: false,
    };
  }

  async openSession(_ctx: SessionCtx): Promise<Session> {
    const now = Date.now();
    this.#session = {
      id: randomUUID(),
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 8 * 60 * 60 * 1000).toISOString(),
    };
    return this.#session;
  }

  async closeSession(_id: string): Promise<void> {
    this.#session = undefined;
    this.#grants.clear();
  }

  async authorizeFill(req: FillRequest): Promise<FillDecision> {
    const binding = this.#bindings.get(req.bindingId);
    // Same answer for "no such binding" and "not allowed": which credentials
    // exist is not something an agent should be able to enumerate.
    if (!binding) {
      return { kind: "denied", reason: "policy_denied", message: "not permitted" };
    }
    if (!this.#session) {
      return { kind: "denied", reason: "session_expired", message: "no open session" };
    }

    const now = Date.now();
    const recent = (this.#issued.get(binding.id) ?? []).filter(
      (t) => now - t < 10 * 60 * 1000,
    );
    if (recent.length >= this.#velocityLimit) {
      return { kind: "denied", reason: "velocity_exceeded", message: "too many fills" };
    }

    const allowed = [...binding.allowedHosts];
    const sso = [...(binding.ssoHosts ?? [])];
    if (!hostAllowed(req.tabOrigin, allowed)) {
      return { kind: "denied", reason: "origin_not_allowed", message: "not permitted" };
    }
    // Evaluated separately from the tab: a cross-origin iframe on an allowed
    // page is how a credential gets read by someone else's document.
    if (!hostAllowed(req.frameOrigin, allowed)) {
      return { kind: "denied", reason: "frame_origin_mismatch", message: "not permitted" };
    }
    // Where the form posts is where the password goes.
    if (!hostAllowed(req.formActionOrigin, allowed)) {
      return { kind: "denied", reason: "form_action_not_allowed", message: "not permitted" };
    }
    // No redirect-chain check here, because `FillRequest` carries no chain to
    // check. The hosted vault evaluates one and the wire type has no field for
    // it, so that rule is presently inert on both backends — the bridge does not
    // yet track where a login has been redirected through. Implementing it means
    // recording navigations during the fill window, which is a real change to
    // the engine rather than something a driver can paper over. `sso` is read
    // below for the policy snapshot only.
    void sso;

    recent.push(now);
    this.#issued.set(binding.id, recent);

    const grantId = randomUUID();
    this.#grants.set(grantId, {
      bindingId: binding.id,
      generation: req.generation,
      expiresAt: now + this.#grantTtlMs,
    });
    return {
      kind: "grant",
      grantId,
      bindingId: binding.id,
      loginUrl: binding.loginUrl,
      expiresAt: new Date(now + this.#grantTtlMs).toISOString(),
      generation: req.generation,
    };
  }

  async consumeFill(grant: Grant): Promise<SecretHandle> {
    const record = this.#grants.get(grant.grantId);
    // Deleted before anything can fail, so a redemption that throws later has
    // still spent the grant. Single use is not "used successfully once".
    this.#grants.delete(grant.grantId);

    if (!record) throw new Error("grant is unknown or already redeemed");
    if (Date.now() > record.expiresAt) throw new Error("grant expired");
    if (record.generation !== grant.generation) throw new Error("page navigated");

    const binding = this.#bindings.get(record.bindingId);
    if (!binding) throw new Error("binding no longer exists");

    // Bytes, not a string handed across: SecretHandle owns the buffer and zeroes
    // it. The string in `binding.secret` is this mock's own compromise, and one
    // of the reasons it says not for production.
    return SecretHandle.adopt(new TextEncoder().encode(binding.secret), `binding:${binding.id}`);
  }

  async audit(event: AuditEvent): Promise<void> {
    this.#onAudit?.(event);
  }

  async policySnapshot(): Promise<GuardrailSnapshot> {
    const all = [...this.#bindings.values()];
    return {
      policyHash: "mock",
      capturedAt: new Date().toISOString(),
      allowedHosts: all.flatMap((b) => [...b.allowedHosts]),
      ssoHosts: all.flatMap((b) => [...(b.ssoHosts ?? [])]),
    };
  }
}

/**
 * Host matching, with the same rules the hosted backend uses.
 *
 * Userinfo is stripped explicitly rather than trusted to a URL parser, because
 * `https://allowed.example@evil.test/` is the classic disguise. A bare list
 * entry matches only itself; a leading dot matches the apex and any subdomain.
 * Anything unparseable denies — "not a URL" is not evidence that it is safe.
 */
function hostAllowed(origin: string, list: readonly string[]): boolean {
  const host = hostOf(origin);
  if (host === undefined) return false;
  return list.some((raw) => {
    const entry = raw.trim().toLowerCase();
    if (entry.startsWith(".")) {
      const suffix = entry.slice(1);
      return host === suffix || host.endsWith(`.${suffix}`);
    }
    return host === entry;
  });
}

function hostOf(value: string): string | undefined {
  if (!value) return undefined;
  const afterScheme = value.includes("://") ? value.slice(value.indexOf("://") + 3) : value;
  const authority = afterScheme.split(/[/?#]/)[0];
  if (authority === undefined || authority === "") return undefined;
  const at = authority.lastIndexOf("@");
  const hostPort = at >= 0 ? authority.slice(at + 1) : authority;
  const host = hostPort.startsWith("[")
    ? hostPort.slice(1).split("]")[0]
    : hostPort.split(":")[0];
  return host ? host.toLowerCase() : undefined;
}
