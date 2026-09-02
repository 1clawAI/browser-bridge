// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { randomUUID } from "node:crypto";
import { readFile, rename, writeFile } from "node:fs/promises";
import type {
  AuditEvent,
  CaptureDecision,
  CaptureRequest,
  RegistrationDecision,
  RegistrationRequest,
  Capabilities,
  FillDecision,
  FillRequest,
  Grant,
  GuardrailSnapshot,
  Session,
  SessionCtx,
} from "@1claw/browser-bridge-protocol";
import { hostAllowed } from "../host-match.js";
import { generatePassword } from "../password-gen.js";
import { SecretHandle } from "../secret-handle.js";
import type { VaultBackend } from "../vault-backend.js";
import {
  openVault,
  sealVault,
  type CapturePolicy,
  type RegistrationPolicy,
  type VaultContents,
  type VaultEntry,
  type VaultFile,
} from "./local-vault-file.js";

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
  /** Human-authored permission to create accounts. Never written by an agent. */
  #registrations = new Map<string, RegistrationPolicy>();
  /** Human-authored permission to capture a site-generated secret. */
  #captures = new Map<string, CapturePolicy>();
  readonly #grants = new Map<
    string,
    { entryId: string; generation: number; expiresAt: number }
  >();
  readonly #issued = new Map<string, number[]>();
  #session: Session | undefined;
  #opened = false;
  /** In-flight registrations: a generated password with nowhere to live yet. */
  readonly #pending = new Map<
    string,
    { siteId: string; password: string; expiresAt: number }
  >();
  /** In-flight captures: which policy a captureId is redeeming. */
  readonly #pendingCaptures = new Map<string, { policyId: string; expiresAt: number }>();

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
    const { entries, registrations, captures } = await this.#decrypt();
    // Both default to empty: a vault with no registration or capture policies
    // is the ordinary case, and the file format does not require the keys.
    this.#registrations = new Map((registrations ?? []).map((r) => [r.id, r]));
    this.#captures = new Map((captures ?? []).map((c) => [c.id, c]));
    this.#index = new Map(
      entries.map((e) => [
        e.id,
        {
          id: e.id,
          loginUrl: e.loginUrl,
          allowedHosts: e.allowedHosts,
          ...(e.ssoHosts ? { ssoHosts: e.ssoHosts } : {}),
          ...(e.username ? { username: e.username } : {}),
          ...(e.usernameSelector ? { usernameSelector: e.usernameSelector } : {}),
          ...(e.submitSelector ? { submitSelector: e.submitSelector } : {}),
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
      // Available exactly when a human has written at least one policy. A
      // backend with none should not advertise the tool: an agent that can see
      // it will call it, and be refused for a reason it cannot act on.
      registration: this.#registrations.size > 0,
      // Same rule as registration: advertised only when a human has authored a
      // policy, so an agent never sees a tool it would only be refused on.
      capture: this.#captures.size > 0,
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
      ...(entry.username ? { username: entry.username } : {}),
      ...(entry.usernameSelector ? { usernameSelector: entry.usernameSelector } : {}),
      ...(entry.submitSelector ? { submitSelector: entry.submitSelector } : {}),
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
    const { entries } = await this.#decrypt();
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

  /**
   * Begin one account creation.
   *
   * The agent names a pre-authorised site and nothing else. Everything that
   * decides where a credential ends up — host, signup URL, username, selectors
   * — comes from the policy a human wrote.
   *
   * The password is generated here and held in this process. It is not in the
   * returned grant, because that object is shaped by what the agent may see.
   */
  async beginRegistration(req: RegistrationRequest): Promise<RegistrationDecision> {
    const policy = this.#registrations.get(req.siteId);
    // Same answer as "not allowed": which sites are pre-authorised is not
    // something an agent gets to enumerate by probing ids.
    if (!policy) {
      return { kind: "denied", reason: "policy_denied", message: "not permitted" };
    }
    if (!this.#session) {
      return { kind: "denied", reason: "session_expired", message: "no open session" };
    }
    // One at a time. Two concurrent registrations against one site produce two
    // accounts, and only one of them ends up in the vault.
    if ([...this.#pending.values()].some((p) => p.siteId === policy.id)) {
      return { kind: "denied", reason: "fill_in_progress", message: "already registering" };
    }

    const registrationId = randomUUID();
    this.#pending.set(registrationId, {
      siteId: policy.id,
      password: generatePassword(policy.passwordPolicy ?? {}),
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    return {
      kind: "registration_grant",
      registrationId,
      signupUrl: policy.signupUrl,
      username: policy.username,
      usernameSelector: policy.usernameSelector,
      passwordSelector: policy.passwordSelector,
      ...(policy.submitSelector ? { submitSelector: policy.submitSelector } : {}),
      success: policy.success,
    };
  }

  /**
   * The generated password, for typing. Same contract as `consumeFill`.
   *
   * Not single-use: a site may reject the password and the engine may retype it
   * after a correction. It is discarded by commit or cancel, and expires with
   * the pending registration.
   */
  async takeRegistrationSecret(registrationId: string): Promise<SecretHandle> {
    const pending = this.#pending.get(registrationId);
    if (!pending) throw new Error("no such registration");
    if (Date.now() > pending.expiresAt) {
      this.#pending.delete(registrationId);
      throw new Error("registration expired");
    }
    return SecretHandle.adopt(
      new TextEncoder().encode(pending.password),
      `registration:${pending.siteId}`,
    );
  }

  /**
   * Write the credential, now that the site has accepted it.
   *
   * Called only after the engine has confirmed success. Committing earlier
   * would store a password the site rejected, and the failure would surface
   * weeks later as a fill that cannot log in.
   *
   * Re-reads and rewrites the file, so the new entry is encrypted under the
   * same passphrase and lands with the rest.
   */
  async commitRegistration(registrationId: string): Promise<{ bindingId: string }> {
    const pending = this.#pending.get(registrationId);
    if (!pending) throw new Error("no such registration");
    const policy = this.#registrations.get(pending.siteId);
    if (!policy) throw new Error("registration policy has gone");

    const contents = await this.#decrypt();
    if (contents.entries.some((e) => e.id === policy.id)) {
      this.#pending.delete(registrationId);
      throw new Error(`a credential for ${policy.id} already exists; remove it first`);
    }
    contents.entries.push({
      id: policy.id,
      secret: pending.password,
      loginUrl: policy.loginUrl,
      allowedHosts: policy.allowedHosts,
    });
    await this.#write(contents);

    this.#pending.delete(registrationId);
    this.#index.set(policy.id, {
      id: policy.id,
      loginUrl: policy.loginUrl,
      allowedHosts: policy.allowedHosts,
    });
    return { bindingId: policy.id };
  }

  /** Discard a registration. The generated password is never written. */
  async cancelRegistration(registrationId: string): Promise<void> {
    this.#pending.delete(registrationId);
  }

  /**
   * Begin one capture.
   *
   * The agent names a pre-authorised site and nothing else. Where the value is
   * read from, and the id it is stored under, come from the policy a human
   * wrote. No secret is returned — it does not exist yet, and when it does the
   * engine hands it to `commitCapture`, never back to the agent.
   */
  async beginCapture(req: CaptureRequest): Promise<CaptureDecision> {
    const policy = this.#captures.get(req.siteId);
    // Same answer as "not allowed": which sites are pre-authorised is not
    // something an agent gets to enumerate by probing ids.
    if (!policy) {
      return { kind: "denied", reason: "policy_denied", message: "not permitted" };
    }
    if (!this.#session) {
      return { kind: "denied", reason: "session_expired", message: "no open session" };
    }
    if ([...this.#pendingCaptures.values()].some((p) => p.policyId === policy.id)) {
      return { kind: "denied", reason: "fill_in_progress", message: "already capturing" };
    }

    const captureId = randomUUID();
    this.#pendingCaptures.set(captureId, { policyId: policy.id, expiresAt: Date.now() + 5 * 60 * 1000 });

    return {
      kind: "capture_grant",
      captureId,
      captureUrl: policy.captureUrl,
      source: {
        ...(policy.generateSelector ? { generateSelector: policy.generateSelector } : {}),
        valueSelector: policy.valueSelector,
        ...(policy.valueProp ? { valueProp: policy.valueProp } : {}),
        ...(policy.valueAttr ? { valueAttr: policy.valueAttr } : {}),
      },
      entryId: policy.entryId ?? policy.id,
    };
  }

  /**
   * Store the captured secret, now that the bridge has read it off the page.
   *
   * The value came in from the engine, not the vault, so this is where a
   * captured secret first touches disk. Consumes the handle: it is read once,
   * under the same passphrase the rest of the file uses, and the buffer is
   * zeroed.
   */
  async commitCapture(captureId: string, secret: SecretHandle): Promise<{ entryId: string }> {
    const pending = this.#pendingCaptures.get(captureId);
    if (!pending) throw new Error("no such capture");
    const policy = this.#captures.get(pending.policyId);
    if (!policy) throw new Error("capture policy has gone");
    const entryId = policy.entryId ?? policy.id;

    const contents = await this.#decrypt();
    if (contents.entries.some((e) => e.id === entryId)) {
      this.#pendingCaptures.delete(captureId);
      throw new Error(`a credential for ${entryId} already exists; remove it first`);
    }
    // Read the handle only once we are committed to storing it.
    const value = secret.use((b) => new TextDecoder().decode(b));
    contents.entries.push({
      id: entryId,
      secret: value,
      loginUrl: policy.loginUrl,
      allowedHosts: policy.allowedHosts,
    });
    await this.#write(contents);

    this.#pendingCaptures.delete(captureId);
    this.#index.set(entryId, {
      id: entryId,
      loginUrl: policy.loginUrl,
      allowedHosts: policy.allowedHosts,
    });
    return { entryId };
  }

  /** Discard a capture. Nothing is written. */
  async cancelCapture(captureId: string): Promise<void> {
    this.#pendingCaptures.delete(captureId);
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

  /**
   * Re-encrypt the whole vault.
   *
   * Written to a temporary file in the same directory and renamed over the
   * original, because a partial write here loses every credential in the file —
   * rename is atomic within a filesystem, a truncating write is not. Mode 0600
   * on the temp file too: it holds the same ciphertext, and briefly existing
   * world-readable is still world-readable.
   */
  async #write(contents: VaultContents): Promise<void> {
    const file = await sealVault(contents, this.#opts.passphrase);
    const tmp = `${this.#opts.path}.${randomUUID()}.tmp`;
    await writeFile(tmp, JSON.stringify(file, null, 2), { mode: 0o600 });
    await rename(tmp, this.#opts.path);
  }

  async #decrypt(): Promise<VaultContents> {
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
