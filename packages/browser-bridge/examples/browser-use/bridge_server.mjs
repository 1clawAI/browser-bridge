#!/usr/bin/env node
// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0
//
// Companion process for test_login.py. Starts a real bridge + a tiny login
// site (same shape as examples/demo.mjs and examples/register-login-act.mjs),
// prints the bridge URL and site origin for the Python side to connect to via
// browser-use, then takes line-delimited commands on stdin:
//
//   FILL <target_id>   -> request a fill for that agent-owned target,
//                         retrying an escalating generation guess since this
//                         harness has no access to the bridge's internal
//                         per-target counter (a real MCP client wouldn't need
//                         to guess -- it reads the live generation itself,
//                         the same way mcp-tools.ts does for a real caller).
//   STOP                -> close the bridge and site, exit.
//
// Two processes, one Node and one Python, because that is what actually
// connects to the bridge in this example: browser-use is a Python package,
// and there is nothing to gain from reimplementing its CDP client in JS just
// to keep this example single-language.

import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { startBridge, MockVaultDriver } from "../../dist/index.js";

const PASSWORD = "correct-horse-battery-staple-bu";
const CHROME =
  process.env.ONECLAW_BRIDGE_CHROME ??
  { darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    linux: "/usr/bin/google-chrome" }[process.platform];
if (!CHROME || !existsSync(CHROME)) {
  console.error(`No Chromium at ${CHROME ?? "(unknown)"}. Set ONECLAW_BRIDGE_CHROME.`);
  process.exit(2);
}

// A tiny app: the form posts to /session, a correct password sets a cookie
// and redirects to /welcome, and /welcome only renders the authenticated view
// when that cookie is present. That last part is the actual test: the fill
// happens on a throwaway target the bridge creates itself, never the agent's
// own tab, so the only way to prove the session really landed in the agent's
// shared browser context is to have the agent independently load a page that
// checks for it -- a page that renders the same text unconditionally would
// prove nothing.
const site = createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const signedIn = (req.headers.cookie ?? "").includes("session=ada");
  if (url.pathname === "/session" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const p = new URLSearchParams(body);
      const ok = p.get("username") === "ada@example.com" && p.get("password") === PASSWORD;
      res.writeHead(302, { location: ok ? "/welcome" : "/login?bad=1",
        ...(ok ? { "set-cookie": "session=ada; Path=/" } : {}) }).end();
    });
    return;
  }
  if (url.pathname === "/welcome") {
    res.writeHead(signedIn ? 200 : 401, { "content-type": "text/html" });
    return void res.end(signedIn
      ? `<!doctype html><title>Welcome</title><body><h1 id="ok">Welcome, ada@example.com</h1></body>`
      : `<!doctype html><title>Welcome</title><body><h1 id="anon">not signed in</h1></body>`);
  }
  res.writeHead(200, { "content-type": "text/html" });
  res.end(`<!doctype html><title>Example login</title><body>
    <form action="/session" method="post">
      <input id="username" name="username" value="ada@example.com">
      <input id="password" name="password" type="password">
      <button id="go" type="submit">Log in</button>
    </form></body>`);
});
await new Promise((r) => site.listen(0, "127.0.0.1", r));
const origin = `http://127.0.0.1:${site.address().port}`;

const backend = new MockVaultDriver({
  bindings: [{ id: "example-login", secret: PASSWORD, loginUrl: `${origin}/login`, allowedHosts: ["127.0.0.1"] }],
});

const bridge = await startBridge({
  executablePath: CHROME,
  backend,
  host: "127.0.0.1",
  args: ["--headless=new", ...(process.env.CI && process.platform === "linux"
    ? ["--no-sandbox", "--disable-dev-shm-usage"] : [])],
});

// Machine-readable, one line each, so the Python side doesn't have to guess
// which console line is which.
console.log(`BRIDGE_URL=${bridge.url}`);
console.log(`SITE_URL=${origin}/login`);
console.log(`READY`);

const rl = createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  const [cmd, ...rest] = line.trim().split(/\s+/);
  if (cmd === "FILL") {
    const targetId = rest[0];
    let result;
    // See the file header: no access to the bridge's internal generation
    // counter from outside, so this tries the value a single real navigation
    // should have produced, then escalates on a stale-generation abort.
    for (let gen = 0; gen <= 3; gen++) {
      result = await bridge.callTool(
        "request_fill",
        { binding_id: "example-login", target_id: targetId, selector: "#password" },
        () => ({
          tabOrigin: origin, frameOrigin: origin, formActionOrigin: origin,
          frameId: targetId, generation: gen,
        }),
      );
      if (!(result && result.status === "aborted" && result.reason === "generation_stale")) break;
    }
    console.log(`FILL_RESULT=${JSON.stringify(result)}`);
  } else if (cmd === "STOP") {
    await bridge.close();
    await new Promise((r) => site.close(r));
    process.exit(0);
  }
});
