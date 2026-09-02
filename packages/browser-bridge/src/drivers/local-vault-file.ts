// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { createCipheriv, createDecipheriv, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

// promisify picks the 3-arg overload; scrypt's options form needs an explicit
// signature or TypeScript rejects the call that passes N, r, p and maxmem.
const scryptAsync = promisify(scrypt) as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

/** Bumped when the envelope changes shape. Read before anything else. */
export const VAULT_FORMAT = 1;

/**
 * scrypt parameters. Deliberately expensive.
 *
 * This file sits on a laptop and its whole security is the passphrase, so the
 * cost of one guess is the only thing between an attacker with the file and
 * every credential in it. N=2^17 with r=8 is ~128 MB and a few hundred
 * milliseconds — unnoticeable once per bridge start, and ruinous at scale.
 *
 * They are stored in the file rather than assumed, so raising them later does
 * not orphan existing vaults. They are also authenticated (see `aad`), so an
 * attacker cannot rewrite them down to something cheap and have the file still
 * decrypt.
 */
export const KDF = { N: 1 << 17, r: 8, p: 1, keyLen: 32 } as const;

/**
 * Permission for an agent to create one account, authored by a human.
 *
 * Everything an agent could otherwise choose lives here: the host, the signup
 * URL, the username, the form selectors, and what success looks like. The agent
 * supplies only the `id`.
 *
 * `allowedHosts` is the binding the account will get once it exists, so a
 * registration and the fill that follows it are governed by the same rule.
 */
export type RegistrationPolicy = {
  readonly id: string;
  readonly signupUrl: string;
  readonly username: string;
  readonly allowedHosts: readonly string[];
  readonly usernameSelector: string;
  readonly passwordSelector: string;
  readonly submitSelector?: string;
  readonly success: {
    readonly urlChanges?: boolean;
    readonly selector?: string;
    readonly errorSelector?: string;
  };
  /** Site rules the generated password must satisfy. */
  readonly passwordPolicy?: {
    readonly length?: number;
    readonly lower?: boolean;
    readonly upper?: boolean;
    readonly digits?: boolean;
    readonly symbols?: string;
  };
  /** Where the credential is written once the site accepts it. */
  readonly loginUrl: string;
};

/**
 * Permission for an agent to capture a site-generated secret, authored by a
 * human. The agent supplies only the `id`; everything that decides what gets
 * read and stored is here.
 *
 * `allowedHosts` is the binding the captured secret is written under, so a
 * capture and any later fill of the same credential are governed by one rule.
 */
export type CapturePolicy = {
  readonly id: string;
  /** The page where the secret is generated and shown. */
  readonly captureUrl: string;
  readonly allowedHosts: readonly string[];
  /** A control the bridge clicks to make the secret appear. Omit if already shown. */
  readonly generateSelector?: string;
  /** Where the value is read from once it exists. */
  readonly valueSelector: string;
  /** Read `.value` or `.textContent`; omit to take whichever is non-empty. */
  readonly valueProp?: "value" | "textContent";
  /** Read a named attribute instead (e.g. `data-clipboard-text`); wins over valueProp. */
  readonly valueAttr?: string;
  /** Vault id the captured secret is written under. Defaults to `id`. */
  readonly entryId?: string;
  /** Login URL recorded on the resulting entry, so a later fill is governed too. */
  readonly loginUrl: string;
};

export type VaultEntry = {
  readonly id: string;
  readonly secret: string;
  readonly loginUrl: string;
  readonly allowedHosts: readonly string[];
  readonly ssoHosts?: readonly string[];
  /**
   * A username to type before the password, for login forms that do not
   * pre-fill it. Not a secret. Both must be present to be used.
   */
  readonly username?: string;
  readonly usernameSelector?: string;
  /** A submit button to click, for forms that need the button's own click. */
  readonly submitSelector?: string;
};

/**
 * What the ciphertext decrypts to.
 *
 * Version 1 files hold a bare array of entries. Reading both shapes keeps
 * existing vaults working rather than requiring a migration for a feature their
 * owner may never use.
 */
export type VaultContents = {
  readonly entries: VaultEntry[];
  readonly registrations: RegistrationPolicy[];
  readonly captures: CapturePolicy[];
};

/** The on-disk shape. Everything outside `ciphertext` is public by design. */
export type VaultFile = {
  readonly format: number;
  readonly kdf: { readonly N: number; readonly r: number; readonly p: number; readonly keyLen: number };
  /** base64 */
  readonly salt: string;
  /** base64, 12 bytes */
  readonly nonce: string;
  /** base64, AES-256-GCM over the entries JSON */
  readonly ciphertext: string;
  /** base64, 16 bytes */
  readonly tag: string;
};

/**
 * What the ciphertext is bound to.
 *
 * Without this the header is unauthenticated: an attacker could rewrite `kdf`
 * to N=2 and the file would still decrypt for anyone who then brute-forced the
 * (now trivial) key derivation. Binding the parameters into the AAD makes any
 * edit to them a decryption failure.
 */
function aad(file: Pick<VaultFile, "format" | "kdf" | "salt">): Buffer {
  return Buffer.from(
    JSON.stringify({ format: file.format, kdf: file.kdf, salt: file.salt }),
    "utf8",
  );
}

export async function deriveKey(passphrase: string, salt: Buffer, kdf: VaultFile["kdf"]): Promise<Buffer> {
  // maxmem must be raised explicitly or node refuses the memory N implies.
  return await scryptAsync(passphrase, salt, kdf.keyLen, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: 256 * kdf.N * kdf.r,
  });
}

/** Encrypt entries into a fresh envelope. A new salt and nonce every time. */
export async function sealVault(
  contents: readonly VaultEntry[] | VaultContents,
  passphrase: string,
): Promise<VaultFile> {
  const doc: VaultContents = Array.isArray(contents)
    ? { entries: [...(contents as readonly VaultEntry[])], registrations: [], captures: [] }
    : {
        entries: [...(contents as VaultContents).entries],
        registrations: [...((contents as VaultContents).registrations ?? [])],
        captures: [...((contents as VaultContents).captures ?? [])],
      };
  if (passphrase.length < 12) {
    // The file's only defence. A short passphrase makes the scrypt cost moot.
    throw new Error("passphrase must be at least 12 characters");
  }
  const salt = randomBytes(32);
  const nonce = randomBytes(12);
  const header = { format: VAULT_FORMAT, kdf: { ...KDF }, salt: salt.toString("base64") };
  const key = await deriveKey(passphrase, salt, header.kdf);

  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad(header));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(doc), "utf8")),
    cipher.final(),
  ]);
  key.fill(0);

  return {
    ...header,
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

/** Decrypt a vault. Throws on a wrong passphrase or a tampered file alike. */
export async function openVault(file: VaultFile, passphrase: string): Promise<VaultContents> {
  if (file.format !== VAULT_FORMAT) {
    throw new Error(`unsupported vault format ${file.format}; this build reads ${VAULT_FORMAT}`);
  }
  const salt = Buffer.from(file.salt, "base64");
  const key = await deriveKey(passphrase, salt, file.kdf);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(file.nonce, "base64"));
  decipher.setAAD(aad(file));
  decipher.setAuthTag(Buffer.from(file.tag, "base64"));
  try {
    const plain = Buffer.concat([
      decipher.update(Buffer.from(file.ciphertext, "base64")),
      decipher.final(),
    ]);
    const parsed: unknown = JSON.parse(plain.toString("utf8"));
    plain.fill(0);
    // A v1 file is a bare array. Normalise rather than migrate.
    return Array.isArray(parsed)
      ? { entries: parsed as VaultEntry[], registrations: [], captures: [] }
      : {
          entries: (parsed as VaultContents).entries ?? [],
          registrations: (parsed as VaultContents).registrations ?? [],
          captures: (parsed as VaultContents).captures ?? [],
        };
  } catch {
    // One message for a wrong passphrase and for a tampered file. Telling them
    // apart tells an attacker which of the two they achieved.
    throw new Error("could not open the vault: wrong passphrase, or the file has been altered");
  } finally {
    key.fill(0);
  }
}

/** Constant-time compare, for callers checking a passphrase twice. */
export function sameSecret(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}
