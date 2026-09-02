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

export type VaultEntry = {
  readonly id: string;
  readonly secret: string;
  readonly loginUrl: string;
  readonly allowedHosts: readonly string[];
  readonly ssoHosts?: readonly string[];
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
export async function sealVault(entries: readonly VaultEntry[], passphrase: string): Promise<VaultFile> {
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
    cipher.update(Buffer.from(JSON.stringify(entries), "utf8")),
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
export async function openVault(file: VaultFile, passphrase: string): Promise<VaultEntry[]> {
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
    const entries = JSON.parse(plain.toString("utf8")) as VaultEntry[];
    plain.fill(0);
    return entries;
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
