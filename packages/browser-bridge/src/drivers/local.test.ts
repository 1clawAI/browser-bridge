// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { FillRequest } from "@1claw/browser-bridge-protocol";
import { LocalVaultDriver } from "./local.js";
import { openVault, sealVault, VAULT_FORMAT, type VaultEntry } from "./local-vault-file.js";

const PASSPHRASE = "a-long-enough-passphrase";
const SECRET = "hunter2-local";
const ENTRY: VaultEntry = {
  id: "b1",
  secret: SECRET,
  loginUrl: "https://app.example.com/login",
  allowedHosts: ["app.example.com"],
};

// scrypt at N=2^17 is deliberately slow; these tests pay it several times.
const SLOW = 30_000;

async function vaultFile(entries: readonly VaultEntry[] = [ENTRY]) {
  const dir = mkdtempSync(join(tmpdir(), "1claw-vault-test-"));
  const path = join(dir, "vault.json");
  writeFileSync(path, JSON.stringify(await sealVault(entries, PASSPHRASE)));
  return path;
}

const req = (over: Partial<FillRequest> = {}): FillRequest => ({
  sessionId: "s1",
  bindingId: "b1",
  tabOrigin: "https://app.example.com",
  frameOrigin: "https://app.example.com",
  formActionOrigin: "https://app.example.com",
  frameId: "T1",
  generation: 1,
  ...over,
});

describe("the vault file", () => {
  it("round-trips through seal and open", async () => {
    const file = await sealVault([ENTRY], PASSPHRASE);
    expect(await openVault(file, PASSPHRASE)).toEqual({ entries: [ENTRY], registrations: [] });
  }, SLOW);

  it("still reads a v1 file, which held a bare array", async () => {
    // Registration policies turned the payload into a document. Existing vaults
    // hold an array, and their owners may never use the new feature — so they
    // are normalised on read rather than migrated.
    const file = await sealVault([ENTRY], PASSPHRASE);
    const doc = await openVault(file, PASSPHRASE);
    expect(doc.entries).toEqual([ENTRY]);
    expect(doc.registrations).toEqual([]);
  }, SLOW);

  it("never contains the secret in the clear", async () => {
    const file = await sealVault([ENTRY], PASSPHRASE);
    expect(JSON.stringify(file)).not.toContain(SECRET);
    // Nor base64-encoded plaintext, which would look encrypted at a glance.
    expect(Buffer.from(file.ciphertext, "base64").toString("utf8")).not.toContain(SECRET);
  }, SLOW);

  it("refuses the wrong passphrase", async () => {
    const file = await sealVault([ENTRY], PASSPHRASE);
    await expect(openVault(file, "not-the-passphrase")).rejects.toThrow(/wrong passphrase/);
  }, SLOW);

  it("gives the same message for a wrong passphrase and a tampered file", async () => {
    // Distinguishing them tells an attacker which of the two they achieved.
    const file = await sealVault([ENTRY], PASSPHRASE);
    const bad = { ...file, ciphertext: Buffer.from("nonsense").toString("base64") };
    const a = await openVault(file, "wrong-passphrase-here").catch((e: Error) => e.message);
    const b = await openVault(bad, PASSPHRASE).catch((e: Error) => e.message);
    expect(a).toBe(b);
  }, SLOW);

  it("refuses a file whose KDF cost has been edited down", async () => {
    // The attack the AAD exists to stop: rewrite N to something trivial, then
    // brute-force the now-cheap derivation. The header is authenticated, so any
    // edit to it breaks decryption instead.
    const file = await sealVault([ENTRY], PASSPHRASE);
    const weakened = { ...file, kdf: { ...file.kdf, N: 2 } };
    await expect(openVault(weakened, PASSPHRASE)).rejects.toThrow();
  }, SLOW);

  it("refuses a short passphrase at seal time", async () => {
    // The file's only defence. Refusing early beats a vault that feels safe.
    await expect(sealVault([ENTRY], "short")).rejects.toThrow(/at least 12/);
  });

  it("refuses a format it does not know", async () => {
    const file = await sealVault([ENTRY], PASSPHRASE);
    await expect(openVault({ ...file, format: VAULT_FORMAT + 1 }, PASSPHRASE)).rejects.toThrow(
      /unsupported vault format/,
    );
  }, SLOW);

  it("uses a fresh salt and nonce every seal", async () => {
    // Reusing a nonce under one key is catastrophic for GCM.
    const a = await sealVault([ENTRY], PASSPHRASE);
    const b = await sealVault([ENTRY], PASSPHRASE);
    expect(a.salt).not.toBe(b.salt);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  }, SLOW);
});

describe("the local driver", () => {
  it("fails on a bad passphrase at open, not at the first fill", async () => {
    // Otherwise a person points an agent at a browser and believes it works.
    const path = await vaultFile();
    const d = new LocalVaultDriver({ path, passphrase: "wrong-passphrase-x" });
    await expect(d.open()).rejects.toThrow(/wrong passphrase/);
  }, SLOW);

  it("refuses a session before open()", async () => {
    const path = await vaultFile();
    const d = new LocalVaultDriver({ path, passphrase: PASSPHRASE });
    await expect(
      d.openSession({ clientId: "c", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" }),
    ).rejects.toThrow(/call open\(\)/);
  }, SLOW);

  it("fills, and hands the secret back exactly once", async () => {
    const path = await vaultFile();
    const d = new LocalVaultDriver({ path, passphrase: PASSPHRASE });
    await d.open();
    await d.openSession({ clientId: "c", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });

    const grant = await d.authorizeFill(req());
    if (grant.kind !== "grant") throw new Error(`expected a grant, got ${grant.kind}`);
    const handle = await d.consumeFill(grant);
    expect(handle.use((b) => new TextDecoder().decode(b))).toBe(SECRET);
    await expect(d.consumeFill(grant)).rejects.toThrow(/unknown or already redeemed/);
  }, SLOW);

  it("applies the same host rules as every other backend", async () => {
    const path = await vaultFile();
    const d = new LocalVaultDriver({ path, passphrase: PASSPHRASE });
    await d.open();
    await d.openSession({ clientId: "c", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });

    for (const bad of [
      "https://evil-app.example.com",
      "https://app.example.com.evil.test",
      "https://app.example.com@evil.test",
    ]) {
      const out = await d.authorizeFill(
        req({ tabOrigin: bad, frameOrigin: bad, formActionOrigin: bad }),
      );
      expect(out.kind, bad).toBe("denied");
    }
    // The iframe and the form action are checked separately from the tab.
    expect(await d.authorizeFill(req({ frameOrigin: "https://evil.test" }))).toMatchObject({
      reason: "frame_origin_mismatch",
    });
    expect(await d.authorizeFill(req({ formActionOrigin: "https://evil.test" }))).toMatchObject({
      reason: "form_action_not_allowed",
    });
  }, SLOW);

  it("holds no plaintext secret between fills", async () => {
    // The reason consumeFill decrypts again rather than caching: a memory
    // capture of a long-running bridge should not yield the whole file.
    const path = await vaultFile();
    const d = new LocalVaultDriver({ path, passphrase: PASSPHRASE });
    await d.open();
    const dumped = JSON.stringify(d, (_k, v) => (typeof v === "bigint" ? String(v) : v));
    expect(dumped).not.toContain(SECRET);
    const snapshot = await d.policySnapshot();
    expect(JSON.stringify(snapshot)).not.toContain(SECRET);
  }, SLOW);
});
