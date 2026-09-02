// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
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
import { hostAllowed } from "../host-match.js";
import { SecretHandle } from "../secret-handle.js";
import type { VaultBackend } from "../vault-backend.js";
import { openVault, type VaultEntry, type VaultFile } from "./local-vault-file.js";

export type LocalVaultDriverOptions = {
  /** Path to the encrypted vault file. */
  readonly path: string;
  /**
   * Passphrase for that file.
   *
   * Read from the environment or a prompt by the caller — never from argv,
   * which is world-readable in `ps` on most systems.
   */
  readonly passphrase: string;
  readonly velocityLimit?: number;
  readonly grantTtlSeconds?: number;
  readonly onAudit?: (event: AuditEvent) => void;
};

const DEFAULT_VELOCITY_LIMIT = 5;
const DEFAULT_GRANT_TTL_SECONDS = 60;

/**
 * A vault that is a file on your machine.
 *
 * The community backend: no account, no server, no network. Credentials live
 * in an AES-256-GCM envelope keyed by scrypt from a passphrase you hold, and
 * the bridge types them into pages exactly as the hosted backend does.
 *
 * **Plaintext exists only during a redemption.** The decrypted entries are not
 * held for the life of the process: `open()` verifies the passphrase and
 * immediately discards what it read, and `consumeFill` decrypts again for the
 * one entry it needs, then zeroes it. That costs an scrypt derivation per fill,
 * which is the point — a memory capture of a long-running bridge should not
 * yield every credential in the file, and the fill path is not hot.
 *
 * The rules a fill must satisfy are the shared ones: exact host match with
 * leading-dot subdomains, tab, frame and form-action checked independently,
 * a velocity cap, and single-use grants that expire. A driver may refuse a
 * fill; it can never widen what the core allows.
 */
export class LocalVaultDriver implements VaultBackend {
  readonly #opts: LocalVaultDriverOptions;
  readonly #velocityLimit: number;
  readonly #grantTtlMs: number;

  /** Public metadata only — never the secret. Populated by `open()`. */
  #index = new Map<string, Omit<VaultEntry, "secret">>();
  readonly #grants = new Map<
    string,
    { entryId: string; generation: number; expiresAt: number }
  >();
  readonly #issued = new Map<string, number[]>();
  #session: Session | undefined;
  #opened = false;

  constructor(opts: LocalVaultDriverOptions) {
    this.#opts = opts;
    this.#velocityLimit = opts.velocityLimit ?? DEFAULT_VELOCITY_LIMIT;
    this.#grantTtlMs = (opts.grantTtlSeconds ?? DEFAULT_GRANT_TTL_SECONDS) * 1000;
  }

  /**
   * Verify the passphrase and learn which bindings exist.
   *
   * Call once at startup so a wrong passphrase fails immediately rather than at
   * the first fill, by which point a person has already pointed an agent at a
   * browser and believes the thing is working.
   */
  async open(): Promise<void> {
    const entries = await this.#decrypt();
    this.#index = new Map(
      entries.map((e) => [
        e.id,
        {
          id: e.id,
          loginUrl: e.loginUrl,
          allowedHosts: e.allowedHosts,
          ...(e.ssoHosts ? { ssoHosts: e.ssoHosts } : {}),
        },
      ]),
    );
    // Deliberately not retained. The index above holds no secret material.
    entries.length = 0;
    this.#opened = true;
  }

  capabilities(): Capabilities {
    return {
      fills: true,
      // A local file has no approval queue, no central audit and no shared
      // policy to report on. Absent rather than present-and-failing.
      registration: false,
      checkout: false,
      signing: false,
      hitl: false,
      centralAudit: false,
      shadowReports: false,
    };
  }

  async openSession(_ctx: SessionCtx): Promise<Session> {
    if (!this.#opened) {
      throw new Error("call open() before starting a session, so a bad passphrase fails early");
    }
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
    const entry = this.#index.get(req.bindingId);
    // Same answer as "not allowed": which credentials exist is not something an
    // agent gets to enumerate by probing ids.
    if (!entry) {
      return { kind: "denied", reason: "policy_denied", message: "not permitted" };
    }
    if (!this.#session) {
      return { kind: "denied", reason: "session_expired", message: "no open session" };
    }

    const now = Date.now();
    const recent = (this.#issued.get(entry.id) ?? []).filter((t) => now - t < 10 * 60 * 1000);
    if (recent.length >= this.#velocityLimit) {
      return { kind: "denied", reason: "velocity_exceeded", message: "too many fills" };
    }

    const allowed = [...entry.allowedHosts];
    if (!hostAllowed(req.tabOrigin, allowed)) {
      return { kind: "denied", reason: "origin_not_allowed", message: "not permitted" };
    }
    if (!hostAllowed(req.frameOrigin, allowed)) {
      return { kind: "denied", reason: "frame_origin_mismatch", message: "not permitted" };
    }
    if (!hostAllowed(req.formActionOrigin, allowed)) {
      return { kind: "denied", reason: "form_action_not_allowed", message: "not permitted" };
    }

    recent.push(now);
    this.#issued.set(entry.id, recent);

    const grantId = randomUUID();
    this.#grants.set(grantId, {
      entryId: entry.id,
      generation: req.generation,
      expiresAt: now + this.#grantTtlMs,
    });
    return {
      kind: "grant",
      grantId,
      bindingId: entry.id,
      loginUrl: entry.loginUrl,
      expiresAt: new Date(now + this.#grantTtlMs).toISOString(),
      generation: req.generation,
    };
  }

  async consumeFill(grant: Grant): Promise<SecretHandle> {
    const record = this.#grants.get(grant.grantId);
    // Spent before anything can fail. Single use means used, not used
    // successfully — an error must not return the grant to the pool.
    this.#grants.delete(grant.grantId);

    if (!record) throw new Error("grant is unknown or already redeemed");
    if (Date.now() > record.expiresAt) throw new Error("grant expired");
    if (record.generation !== grant.generation) throw new Error("page navigated");

    // Decrypt now, for this one fill, rather than holding plaintext for the
    // life of the process.
    const entries = await this.#decrypt();
    try {
      const entry = entries.find((e) => e.id === record.entryId);
      if (!entry) throw new Error("binding no longer exists in the vault file");
      return SecretHandle.adopt(new TextEncoder().encode(entry.secret), `binding:${entry.id}`);
    } finally {
      // Best effort: these are JS strings and cannot truly be wiped, which is
      // why the window is kept short rather than treated as safe.
      entries.length = 0;
    }
  }

  async audit(event: AuditEvent): Promise<void> {
    this.#opts.onAudit?.(event);
  }

  async policySnapshot(): Promise<GuardrailSnapshot> {
    const all = [...this.#index.values()];
    return {
      policyHash: "local",
      capturedAt: new Date().toISOString(),
      allowedHosts: all.flatMap((e) => [...e.allowedHosts]),
      ssoHosts: all.flatMap((e) => [...(e.ssoHosts ?? [])]),
    };
  }

  async #decrypt(): Promise<VaultEntry[]> {
    const raw = await readFile(this.#opts.path, "utf8");
    let file: VaultFile;
    try {
      file = JSON.parse(raw) as VaultFile;
    } catch {
      throw new Error(`${this.#opts.path} is not a vault file`);
    }
    return openVault(file, this.#opts.passphrase);
  }
}
