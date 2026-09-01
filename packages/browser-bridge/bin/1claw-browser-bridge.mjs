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
 *   1claw-browser-bridge --chrome /path/to/chrome
 *
 * Env:
 *   ONECLAW_API_URL            vault base (default https://api.1claw.co)
 *   ONECLAW_BRIDGE_CREDENTIAL  the bb_ credential from `1claw browser-bridge login`
 *   ONECLAW_BRIDGE_PORT        loopback port (default: ephemeral)
 */

import { startBridge, SaasDriver } from "../dist/index.js";
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

const backend = new SaasDriver({
  baseUrl: (process.env.ONECLAW_API_URL || "https://api.1claw.co").replace(/\/$/, ""),
  bridgeCredential: credential,
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
