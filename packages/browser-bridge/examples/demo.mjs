#!/usr/bin/env node
// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * Watch a credential get typed into a page that an agent is driving, without
 * the agent ever seeing it.
 *
 * No account, no network, no 1Claw API. A local HTTP server serves a login
 * form, MockVaultDriver holds the password in memory, and a real Chromium does
 * the typing. Everything the agent would receive is printed, so you can check
 * for yourself that the secret is not in it.
 *
 *   node examples/demo.mjs [--chrome /path/to/chrome]
 */

import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { startBridge, MockVaultDriver } from "../dist/index.js";

const PASSWORD = "correct-horse-battery-staple";
const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf(`--${n}`); return i > -1 ? argv[i + 1] : undefined; };

const CHROME =
  flag("chrome") ??
  process.env.ONECLAW_BRIDGE_CHROME ??
  { darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    linux: "/usr/bin/google-chrome" }[process.platform];

if (!CHROME || !existsSync(CHROME)) {
  console.error(`No Chromium at ${CHROME ?? "(unknown)"}. Pass --chrome /path/to/chrome.`);
  process.exit(2);
}

// ── A site to log in to ──────────────────────────────────────────────────────
const site = createServer((_req, res) => {
  res.writeHead(200, { "content-type": "text/html" });
  res.end(`<!doctype html><title>Example login</title><body>
    <form action="/session" method="post">
      <input id="username" name="username" value="ada@example.com">
      <input id="password" name="password" type="password">
    </form></body>`);
});
await new Promise((r) => site.listen(0, "127.0.0.1", r));
const origin = `http://127.0.0.1:${site.address().port}`;

// ── The vault, in memory ─────────────────────────────────────────────────────
const audits = [];
const backend = new MockVaultDriver({
  bindings: [{
    id: "example-login",
    secret: PASSWORD,
    loginUrl: origin,
    // 127.0.0.1 because that is where the demo site is. A real binding names
    // the site's own hostname, and nothing else will match.
    allowedHosts: ["127.0.0.1"],
  }],
  onAudit: (e) => audits.push(e),
});

const bridge = await startBridge({
  executablePath: CHROME,
  backend,
  host: "127.0.0.1",
  args: ["--headless=new", ...(process.env.CI && process.platform === "linux"
    ? ["--no-sandbox", "--disable-dev-shm-usage"] : [])],
});

console.log(`\n  site:   ${origin}`);
console.log(`  bridge: ${bridge.url}`);
console.log(`  tools:  ${bridge.tools.map((t) => t.name).join(", ")}\n`);

try {
  // ── The agent asks for a fill ──────────────────────────────────────────────
  // It supplies a binding id and where to type. It does not supply the URL —
  // the bridge navigates to the binding's own login_url — and it never receives
  // the value.
  const result = await bridge.callTool(
    "request_fill",
    { binding_id: "example-login", target_id: "agent-tab", selector: "#password" },
    // What the bridge reads off the live page. Not what the agent claims.
    () => ({
      tabOrigin: origin, frameOrigin: origin, formActionOrigin: origin,
      frameId: "agent-tab", generation: 0,
    }),
  );

  console.log("  what the agent received:");
  console.log(`    ${JSON.stringify(result)}\n`);

  const leaked = JSON.stringify(result).includes(PASSWORD);
  console.log(`  password present in the agent's result: ${leaked ? "YES — BUG" : "no"}`);

  // ── And the same request from a page it is not allowed on ─────────────────
  const denied = await bridge.callTool(
    "request_fill",
    { binding_id: "example-login", target_id: "agent-tab", selector: "#password" },
    () => ({
      tabOrigin: "https://evil.test", frameOrigin: "https://evil.test",
      formActionOrigin: "https://evil.test", frameId: "agent-tab", generation: 0,
    }),
  );
  console.log(`  same fill on an unlisted host:          ${JSON.stringify(denied)}`);

  if (audits.length) {
    console.log(`\n  audit events: ${audits.length}`);
    for (const a of audits) console.log(`    ${a.type}`);
  }
  console.log("");
  process.exitCode = leaked ? 1 : 0;
} finally {
  await bridge.close();
  await new Promise((r) => site.close(r));
}
