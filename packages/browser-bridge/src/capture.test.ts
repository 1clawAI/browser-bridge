// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LocalVaultDriver } from "./drivers/local.js";
import { openVault, sealVault, type CapturePolicy } from "./drivers/local-vault-file.js";
import { SecretHandle } from "./secret-handle.js";

const PASSPHRASE = "a-long-enough-passphrase";
const SLOW = 30_000;

const POLICY: CapturePolicy = {
  id: "acme-key",
  captureUrl: "https://acme.example.com/settings/api",
  loginUrl: "https://acme.example.com/login",
  allowedHosts: ["acme.example.com"],
  generateSelector: "#generate",
  valueSelector: "#api-key",
  valueProp: "value",
};

async function vault(captures: CapturePolicy[] = [POLICY]) {
  const dir = mkdtempSync(join(tmpdir(), "1claw-capture-test-"));
  const path = join(dir, "vault.json");
  writeFileSync(path, JSON.stringify(await sealVault({ entries: [], registrations: [], captures }, PASSPHRASE)));
  const d = new LocalVaultDriver({ path, passphrase: PASSPHRASE });
  await d.open();
  await d.openSession({ clientId: "c", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
  return { d, path };
}

describe("what the agent can and cannot choose", () => {
  it("takes the URL, source and destination from the policy, not the request", async () => {
    const { d } = await vault();
    const out = await d.beginCapture({ siteId: "acme-key" });
    expect(out).toMatchObject({
      kind: "capture_grant",
      captureUrl: POLICY.captureUrl,
      entryId: "acme-key",
      source: { generateSelector: "#generate", valueSelector: "#api-key", valueProp: "value" },
    });
    // The request type has nowhere to put an alternative.
    expect(Object.keys({ siteId: "acme-key" })).toEqual(["siteId"]);
  }, SLOW);

  it("refuses a site nobody authorised, without saying it is unknown", async () => {
    const { d } = await vault();
    expect(await d.beginCapture({ siteId: "evil" })).toMatchObject({ kind: "denied", reason: "policy_denied" });
  }, SLOW);

  it("never puts a secret in the grant", async () => {
    const { d } = await vault();
    const grant = await d.beginCapture({ siteId: "acme-key" });
    // There is nothing to leak — the value does not exist yet — but the shape
    // must have no place for one regardless.
    expect(JSON.stringify(grant)).not.toMatch(/secret["']?\s*:/i);
    expect(Object.keys(grant as object)).not.toContain("secret");
  }, SLOW);

  it("advertises the capability only when a policy exists", async () => {
    const { d: withPolicy } = await vault();
    expect(withPolicy.capabilities().capture).toBe(true);
    const { d: without } = await vault([]);
    expect(without.capabilities().capture).toBe(false);
  }, SLOW);

  it("refuses two captures for one site at once", async () => {
    const { d } = await vault();
    expect((await d.beginCapture({ siteId: "acme-key" })).kind).toBe("capture_grant");
    expect(await d.beginCapture({ siteId: "acme-key" })).toMatchObject({ reason: "fill_in_progress" });
  }, SLOW);
});

describe("nothing is stored unless the value was read", () => {
  it("writes no credential when the capture is cancelled", async () => {
    const { d, path } = await vault();
    const grant = await d.beginCapture({ siteId: "acme-key" });
    if (grant.kind !== "capture_grant") throw new Error("expected a grant");
    await d.cancelCapture(grant.captureId);
    const doc = await openVault(JSON.parse(await readFile(path, "utf8")), PASSPHRASE);
    expect(doc.entries).toHaveLength(0);
  }, SLOW);

  it("writes the captured secret on commit, encrypted, and usable as a binding", async () => {
    const { d, path } = await vault();
    const grant = await d.beginCapture({ siteId: "acme-key" });
    if (grant.kind !== "capture_grant") throw new Error("expected a grant");

    const KEY = "sk-live-abc123-the-captured-key";
    const handle = SecretHandle.adopt(new TextEncoder().encode(KEY), "test");
    const { entryId } = await d.commitCapture(grant.captureId, handle);
    expect(entryId).toBe("acme-key");

    const raw = await readFile(path, "utf8");
    expect(raw).not.toContain(KEY); // encrypted at rest
    const doc = await openVault(JSON.parse(raw), PASSPHRASE);
    expect(doc.entries).toHaveLength(1);
    expect(doc.entries[0]).toMatchObject({
      id: "acme-key",
      secret: KEY,
      loginUrl: POLICY.loginUrl,
      allowedHosts: POLICY.allowedHosts,
    });
  }, SLOW);

  it("stores under a distinct entry-id when the policy names one", async () => {
    const { d } = await vault([{ ...POLICY, entryId: "acme-api-token" }]);
    const grant = await d.beginCapture({ siteId: "acme-key" });
    if (grant.kind !== "capture_grant") throw new Error("expected a grant");
    expect(grant.entryId).toBe("acme-api-token");
    const { entryId } = await d.commitCapture(
      grant.captureId,
      SecretHandle.adopt(new TextEncoder().encode("k"), "t"),
    );
    expect(entryId).toBe("acme-api-token");
  }, SLOW);

  it("refuses to overwrite a credential that already exists", async () => {
    const { d } = await vault();
    const g1 = await d.beginCapture({ siteId: "acme-key" });
    if (g1.kind !== "capture_grant") throw new Error("expected a grant");
    await d.commitCapture(g1.captureId, SecretHandle.adopt(new TextEncoder().encode("first"), "t"));

    const g2 = await d.beginCapture({ siteId: "acme-key" });
    if (g2.kind !== "capture_grant") throw new Error("expected a grant");
    await expect(
      d.commitCapture(g2.captureId, SecretHandle.adopt(new TextEncoder().encode("second"), "t")),
    ).rejects.toThrow(/already exists/);
  }, SLOW);
});
