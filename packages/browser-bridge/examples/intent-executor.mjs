// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * A minimal local stand-in for the 1Claw Execution Intents API
 * (`POST /v1/agents/{id}/execute`), so the capture examples can close the loop
 * without a hosted account.
 *
 * The shape is the platform's: a human authors a binding — which vaulted secret,
 * and how it is injected into one outbound request. The agent calls
 * `executeIntent` with the binding id and some params, and gets the response
 * back. It never sees the secret. The executor holds the vault passphrase, the
 * way the hosted runtime holds the key inside the TEE, and injects the secret
 * itself.
 *
 * This is a demonstration executor, not the production path — the hosted Intents
 * API runs the request inside a TEE with guardrails, rate limits, and audit.
 * What it shows is the same property: the credential is used without ever
 * reaching the agent.
 */
import { readFileSync } from "node:fs";
import { openVault } from "../dist/index.js";

/**
 * @param {object} o
 * @param {string} o.vaultPath      path to the encrypted vault
 * @param {string} o.passphrase     its passphrase (the executor is trusted)
 * @param {object} o.binding        { method?, url, secretEntryId, inject }
 *   inject: { as: 'query', name } | { as: 'header', name, template? }
 *   `url` and header `template` may contain {{param}} and, for a header,
 *   {{secret}} — the only place the secret is ever substituted.
 * @param {Record<string,string>} [o.params]
 * @returns {Promise<{status:number, body:string}>}
 */
export async function executeIntent({ vaultPath, passphrase, binding, params = {} }) {
  const doc = await openVault(JSON.parse(readFileSync(vaultPath, "utf8")), passphrase);
  const entry = doc.entries.find((e) => e.id === binding.secretEntryId);
  if (!entry) throw new Error(`no vaulted secret "${binding.secretEntryId}"`);
  const secret = entry.secret;

  const fill = (s) => s.replace(/\{\{(\w+)\}\}/g, (_, k) => encodeURIComponent(params[k] ?? ""));
  let url = fill(binding.url);
  const headers = {};

  if (binding.inject.as === "query") {
    const u = new URL(url);
    u.searchParams.set(binding.inject.name, secret); // the secret goes on the wire, never to the agent
    url = u.toString();
  } else {
    headers[binding.inject.name] = (binding.inject.template ?? "{{secret}}").replace("{{secret}}", secret);
  }

  const res = await fetch(url, { method: binding.method ?? "GET", headers });
  return { status: res.status, body: await res.text() };
}
