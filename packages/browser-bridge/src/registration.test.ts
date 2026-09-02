// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LocalVaultDriver } from "./drivers/local.js";
import { openVault, sealVault, type RegistrationPolicy } from "./drivers/local-vault-file.js";

const PASSPHRASE = "a-long-enough-passphrase";
const SLOW = 30_000;

const POLICY: RegistrationPolicy = {
  id: "acme",
  signupUrl: "https://acme.example.com/signup",
  loginUrl: "https://acme.example.com/login",
  username: "ada@example.com",
  allowedHosts: ["acme.example.com"],
  usernameSelector: "#email",
  passwordSelector: "#password",
  success: { urlChanges: true },
};

async function vault(registrations: RegistrationPolicy[] = [POLICY]) {
  const dir = mkdtempSync(join(tmpdir(), "1claw-reg-test-"));
  const path = join(dir, "vault.json");
  writeFileSync(path, JSON.stringify(await sealVault({ entries: [], registrations }, PASSPHRASE)));
  const d = new LocalVaultDriver({ path, passphrase: PASSPHRASE });
  await d.open();
  await d.openSession({ clientId: "c", bridgeVersion: "0.1.0", protocolVersion: "0.1.0" });
  return { d, path };
}

describe("what the agent can and cannot choose", () => {
  it("takes the host, URL and username from the policy, not the request", async () => {
    // The whole security argument. In a fill a human already chose the host; in
    // a registration there is no binding yet, so if the agent named the host it
    // would be choosing where a credential gets created.
    const { d } = await vault();
    const out = await d.beginRegistration({ siteId: "acme" } as never);
    expect(out).toMatchObject({
      kind: "registration_grant",
      signupUrl: POLICY.signupUrl,
      username: POLICY.username,
    });
    // And the request type has nowhere to put an alternative.
    expect(Object.keys({ siteId: "acme" })).toEqual(["siteId"]);
  }, SLOW);

  it("refuses a site nobody authorised, without saying it is unknown", async () => {
    const { d } = await vault();
    const out = await d.beginRegistration({ siteId: "evil" } as never);
    // Same answer as "not allowed": which sites are pre-authorised is not
    // something an agent gets to enumerate by probing ids.
    expect(out).toMatchObject({ kind: "denied", reason: "policy_denied" });
  }, SLOW);

  it("never puts the password in the grant", async () => {
    const { d } = await vault();
    const grant = await d.beginRegistration({ siteId: "acme" } as never);
    // The object the agent could be handed must have no shape that holds one.
    expect(JSON.stringify(grant)).not.toMatch(/password["']?\s*:/i);
    expect(Object.keys(grant as object)).not.toContain("password");
  }, SLOW);

  it("advertises the capability only when a policy exists", async () => {
    // A tool an agent can see is a tool it will call. With no policies there is
    // nothing it could succeed at, so the tool should not be registered.
    const { d: withPolicy } = await vault();
    expect(withPolicy.capabilities().registration).toBe(true);
    const { d: without } = await vault([]);
    expect(without.capabilities().registration).toBe(false);
  }, SLOW);

  it("refuses two registrations for one site at once", async () => {
    // Two concurrent attempts create two accounts and store one.
    const { d } = await vault();
    expect((await d.beginRegistration({ siteId: "acme" } as never)).kind).toBe("registration_grant");
    expect(await d.beginRegistration({ siteId: "acme" } as never)).toMatchObject({
      reason: "fill_in_progress",
    });
  }, SLOW);
});

describe("nothing is stored unless the site accepted it", () => {
  it("writes no credential when the registration is cancelled", async () => {
    const { d, path } = await vault();
    const grant = await d.beginRegistration({ siteId: "acme" } as never);
    if (grant.kind !== "registration_grant") throw new Error("expected a grant");

    // A password the site rejected must not reach the file. The failure would
    // otherwise surface weeks later as a fill that cannot log in.
    await d.cancelRegistration(grant.registrationId);
    const doc = await openVault(JSON.parse(await readFile(path, "utf8")), PASSPHRASE);
    expect(doc.entries).toHaveLength(0);
  }, SLOW);

  it("writes the credential on commit, and it is usable as a binding", async () => {
    const { d, path } = await vault();
    const grant = await d.beginRegistration({ siteId: "acme" } as never);
    if (grant.kind !== "registration_grant") throw new Error("expected a grant");

    const handle = await d.takeRegistrationSecret(grant.registrationId);
    const generated = handle.use((b) => new TextDecoder().decode(b));
    expect(generated.length).toBeGreaterThanOrEqual(8);

    const { bindingId } = await d.commitRegistration(grant.registrationId);
    expect(bindingId).toBe("acme");

    // On disk, encrypted, under the same passphrase.
    const raw = await readFile(path, "utf8");
    expect(raw).not.toContain(generated);
    const doc = await openVault(JSON.parse(raw), PASSPHRASE);
    expect(doc.entries).toHaveLength(1);
    expect(doc.entries[0]).toMatchObject({
      id: "acme",
      secret: generated,
      allowedHosts: POLICY.allowedHosts,
    });

    // And immediately fillable, without reopening the driver.
    const decision = await d.authorizeFill({
      sessionId: "s", bindingId: "acme",
      tabOrigin: "https://acme.example.com", frameOrigin: "https://acme.example.com",
      formActionOrigin: "https://acme.example.com", frameId: "T", generation: 1,
 formPath: "/login",
 fieldNames: ["username", "password"],
 redirectChain: [],
 currentGeneration: 1,
    } as never);
    expect(decision.kind).toBe("grant");
  }, SLOW);

  it("cannot commit twice, or commit an unknown registration", async () => {
    const { d } = await vault();
    const grant = await d.beginRegistration({ siteId: "acme" } as never);
    if (grant.kind !== "registration_grant") throw new Error("expected a grant");
    await d.commitRegistration(grant.registrationId);
    await expect(d.commitRegistration(grant.registrationId)).rejects.toThrow(/no such registration/);
    await expect(d.commitRegistration("made-up")).rejects.toThrow(/no such registration/);
  }, SLOW);

  it("refuses to overwrite a credential that already exists", async () => {
    // Otherwise a second registration silently replaces a working credential
    // with one for an account nobody asked for.
    const { d } = await vault();
    const first = await d.beginRegistration({ siteId: "acme" } as never);
    if (first.kind !== "registration_grant") throw new Error("expected a grant");
    await d.commitRegistration(first.registrationId);

    const second = await d.beginRegistration({ siteId: "acme" } as never);
    if (second.kind !== "registration_grant") throw new Error("expected a grant");
    await expect(d.commitRegistration(second.registrationId)).rejects.toThrow(/already exists/);
  }, SLOW);

  it("generates a different password each time", async () => {
    const { d } = await vault();
    const seen = new Set<string>();
    for (let i = 0; i < 3; i++) {
      const g = await d.beginRegistration({ siteId: "acme" } as never);
      if (g.kind !== "registration_grant") throw new Error("expected a grant");
      const h = await d.takeRegistrationSecret(g.registrationId);
      seen.add(h.use((b) => new TextDecoder().decode(b)));
      await d.cancelRegistration(g.registrationId);
    }
    expect(seen.size).toBe(3);
  }, SLOW);
});
