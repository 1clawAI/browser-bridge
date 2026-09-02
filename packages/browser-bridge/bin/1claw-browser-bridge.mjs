#!/usr/bin/env node
// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * Start a browser bridge.
 *
 * This is the layer that picks a backend. The core deliberately cannot — see
 * core-has-no-driver-conditionals.test.ts — so driver selection lives out here,
 * where it is one decision in one place rather than a branch inside the fill
 * rules.
 *
 * Usage:
 *   1claw-browser-bridge --chrome /path/to/chrome                    # hosted vault
 *   1claw-browser-bridge --vault ~/.1claw/vault.json --chrome ...    # local file
 *
 * Env:
 *   ONECLAW_API_URL            vault base (default https://api.1claw.co)
 *   ONECLAW_BRIDGE_CREDENTIAL  the bb_ credential from `1claw browser-bridge login`
 *   ONECLAW_TOKEN              your user session token or 1ck_ key — opens the
 *                              session and collects the secret
 *   ONECLAW_AGENT_TOKEN        the agent's JWT — asks whether a fill is allowed
 *   ONECLAW_AGENT_ID           the agent fills are requested for
 *   ONECLAW_BRIDGE_PORT        loopback port (default: ephemeral)
 *
 * Three credentials, because the vault requires three distinct things: which
 * machine (bb_), which person (ONECLAW_TOKEN), which agent (ONECLAW_AGENT_TOKEN).
 * Collapsing them would let any one of the three stand in for the others.
 */

import { startBridge, SaasDriver, LocalVaultDriver } from "../dist/index.js";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const argv = process.argv.slice(2);
const arg = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i > -1 ? argv[i + 1] : undefined;
};

const version = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8"),
).version;

const chrome =
  arg("chrome") ||
  process.env.ONECLAW_BRIDGE_CHROME ||
  {
    darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    linux: "/usr/bin/google-chrome",
  }[process.platform];

if (!chrome) {
  console.error("No Chromium found. Pass --chrome /path/to/chrome.");
  process.exit(2);
}

// ── Local vault: your own credentials, no account ────────────────────────────
//
// Checked before the hosted path so `--vault` short-circuits the three env vars
// the SaaS backend needs. A person running the community backend should not be
// told to set ONECLAW_TOKEN.
const vaultPath = arg("vault") || process.env.ONECLAW_BRIDGE_VAULT;
if (vaultPath) {
  const passphrase = process.env.ONECLAW_BRIDGE_VAULT_PASSPHRASE;
  if (!passphrase) {
    console.error("ONECLAW_BRIDGE_VAULT_PASSPHRASE is not set.");
    console.error("Not a flag on purpose: argv is world-readable in `ps`.");
    process.exit(2);
  }
  const local = new LocalVaultDriver({ path: vaultPath, passphrase });
  // Opened here so a wrong passphrase fails now, rather than at the first fill
  // when someone has already pointed an agent at a browser. A wrong passphrase
  // is an ordinary mistake, so it gets one line — not a stack trace that buries
  // the message it needs to convey.
  try {
    await local.open();
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(2);
  }

  const localBridge = await startBridge({
    executablePath: chrome,
    backend: local,
    host: "127.0.0.1",
    ...(process.env.ONECLAW_BRIDGE_PORT ? { port: Number(process.env.ONECLAW_BRIDGE_PORT) } : {}),
  });
  console.log(localBridge.url);
  console.error(`browser bridge ${version} listening on ${localBridge.host}:${localBridge.port}`);
  console.error(`vault: ${vaultPath}`);
  console.error(`tools: ${localBridge.tools.map((t) => t.name).join(", ") || "(none)"}`);
  const stop = async (signal) => {
    console.error(`\n${signal} — closing`);
    await localBridge.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void stop("SIGINT"));
  process.on("SIGTERM", () => void stop("SIGTERM"));
} else {

const credential = process.env.ONECLAW_BRIDGE_CREDENTIAL;
if (!credential) {
  console.error("ONECLAW_BRIDGE_CREDENTIAL is not set. Run: 1claw browser-bridge login");
  process.exit(2);
}
if (!credential.startsWith("bb_")) {
  // A prefix check is not authentication — the vault resolves the credential —
  // but pasting an agent key here would send it to the wrong endpoint entirely.
  console.error("ONECLAW_BRIDGE_CREDENTIAL does not look like a bridge credential (bb_…).");
  process.exit(2);
}

const required = {
  ONECLAW_TOKEN: "your user session token or 1ck_ key",
  ONECLAW_AGENT_TOKEN: "the agent's JWT",
  ONECLAW_AGENT_ID: "the agent id fills are for",
};
for (const [name, what] of Object.entries(required)) {
  if (!process.env[name]) {
    console.error(`${name} is not set (${what}).`);
    process.exit(2);
  }
}

const backend = new SaasDriver({
  baseUrl: (process.env.ONECLAW_API_URL || "https://api.1claw.co").replace(/\/$/, ""),
  bridgeCredential: credential,
  userToken: process.env.ONECLAW_TOKEN,
  agentToken: process.env.ONECLAW_AGENT_TOKEN,
  agentId: process.env.ONECLAW_AGENT_ID,
  bridgeVersion: version,
});

const bridge = await startBridge({
  executablePath: chrome,
  backend,
  host: "127.0.0.1",
  ...(process.env.ONECLAW_BRIDGE_PORT ? { port: Number(process.env.ONECLAW_BRIDGE_PORT) } : {}),
});

// The URL carries the session token, so it is the one secret this process
// prints. It goes to stdout because that is what the caller captures; nothing
// else here writes there.
console.log(bridge.url);
console.error(`browser bridge ${version} listening on ${bridge.host}:${bridge.port}`);
console.error(`tools: ${bridge.tools.map((t) => t.name).join(", ") || "(none)"}`);

const shutdown = async (signal) => {
  console.error(`\n${signal} — closing`);
  await bridge.close();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
}
