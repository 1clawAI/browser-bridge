#!/usr/bin/env node
// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * Manage a local encrypted vault for the browser bridge.
 *
 * DEPRECATED — use `1claw browser vault` instead.
 *
 * Two CLIs whose names differ by a hyphen, one of which shares a word with an
 * unrelated subcommand (`1claw vault` manages *hosted* vaults), is a naming
 * problem nobody can hold in their head. `@1claw/cli` now carries all of this
 * under `1claw browser`, reading and writing this same file through this same
 * implementation — there is no second format.
 *
 * This binary keeps working and prints a pointer. It goes in the next minor.
 *
 *   1claw-vault init   <file>
 *   1claw-vault add    <file> --id <id> --url <login-url> --hosts a.com,.b.com
 *   1claw-vault list   <file>
 *   1claw-vault remove <file> --id <id>
  1claw-vault allow-signup <file> --id <id> --signup <url> --login <url> \\
      --username <value> --hosts a.com --user-sel <css> --pass-sel <css> \\
      [--submit-sel <css>] [--success-sel <css>] [--error-sel <css>]
 *
 * The passphrase comes from ONECLAW_BRIDGE_VAULT_PASSPHRASE, or is prompted for
 * with echo off. Never from a command-line argument: argv is world-readable in
 * `ps` on most systems, and a passphrase there also lands in shell history.
 *
 * The secret itself is read from stdin for the same reason.
 */

import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { sealVault, openVault } from "../dist/drivers/local-vault-file.js";

// Said once, on stderr, so it never contaminates piped output.
if (process.env.ONECLAW_SUPPRESS_DEPRECATION !== "1") {
  process.stderr.write(
    "1claw-vault is deprecated — use `1claw browser vault` (same file, same format).\n" +
      "  Set ONECLAW_SUPPRESS_DEPRECATION=1 to silence this.\n",
  );
}

const [cmd, file, ...rest] = process.argv.slice(2);
const flag = (n) => { const i = rest.indexOf(`--${n}`); return i > -1 ? rest[i + 1] : undefined; };

function usage(code = 2) {
  console.error(`usage:
  1claw-vault init   <file>
  1claw-vault add    <file> --id <id> --url <login-url> --hosts a.com,.b.com [--sso idp.com] [--username <u> --user-sel <css>]
  1claw-vault list   <file>
  1claw-vault remove <file> --id <id>
  1claw-vault allow-capture <file> --id <id> --url <page-url> --login <login-url> \\
      --hosts a.com --value-sel <css> [--generate-sel <css>] \\
      [--value-prop value|textContent] [--entry-id <id>]

hosts: a bare entry matches only itself; a leading dot ('.example.com') matches
that host and any subdomain. '*' is not a wildcard here and is refused.

env: ONECLAW_BRIDGE_VAULT_PASSPHRASE`);
  process.exit(code);
}
if (!cmd || !file) usage();

/** Read a line with the terminal echo off, so it is not shoulder-surfed. */
async function promptHidden(label) {
  if (!process.stdin.isTTY) throw new Error(`${label} required; set ONECLAW_BRIDGE_VAULT_PASSPHRASE`);
  process.stderr.write(label);
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  rl.output.write = () => {};
  const value = await new Promise((r) => rl.question("", r));
  rl.close();
  process.stderr.write("\n");
  return value;
}

async function passphrase() {
  return process.env.ONECLAW_BRIDGE_VAULT_PASSPHRASE ?? (await promptHidden("passphrase: "));
}

async function readStdin() {
  if (process.stdin.isTTY) return await promptHidden("secret: ");
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8").replace(/\n$/, "");
}

async function load(pass) {
  const doc = await openVault(JSON.parse(await readFile(file, "utf8")), pass);
  return { entries: doc.entries ?? [], registrations: doc.registrations ?? [], captures: doc.captures ?? [] };
}
async function save(doc, pass) {
  // 0600: a vault the rest of the machine can read is not a vault.
  await writeFile(file, JSON.stringify(await sealVault(doc, pass), null, 2), { mode: 0o600 });
}

function parseHosts(raw, what) {
  const hosts = (raw ?? "").split(",").map((h) => h.trim()).filter(Boolean);
  for (const h of hosts) {
    if (h.includes("*")) {
      console.error(`'${h}' uses '*'. Subdomains are written with a leading dot: .${h.replace(/^\*\.?/, "")}`);
      process.exit(2);
    }
    if (h.includes("://") || h.includes("/")) {
      console.error(`'${h}' looks like a URL. ${what} takes bare hostnames.`);
      process.exit(2);
    }
  }
  return hosts;
}

try {
  if (cmd === "init") {
    if (existsSync(file)) { console.error(`${file} already exists`); process.exit(2); }
    const pass = await passphrase();
    const again = process.env.ONECLAW_BRIDGE_VAULT_PASSPHRASE ? pass : await promptHidden("again: ");
    if (pass !== again) { console.error("passphrases do not match"); process.exit(2); }
    await save({ entries: [], registrations: [], captures: [] }, pass);
    console.error(`created ${file}`);
  } else if (cmd === "add") {
    const id = flag("id"), url = flag("url");
    if (!id || !url) usage();
    const hosts = parseHosts(flag("hosts"), "--hosts");
    if (hosts.length === 0) { console.error("--hosts must name at least one host"); process.exit(2); }
    if (!url.startsWith("https://") && !url.startsWith("http://127.0.0.1")) {
      // http is only sensible for a local demo; anything else is a credential
      // typed over the wire in the clear.
      console.error("--url must be https (http is allowed only for 127.0.0.1)");
      process.exit(2);
    }
    const pass = await passphrase();
    const doc = await load(pass);
    if (doc.entries.some((e) => e.id === id)) { console.error(`${id} already exists`); process.exit(2); }
    const secret = await readStdin();
    if (!secret) { console.error("empty secret"); process.exit(2); }
    doc.entries.push({
      id, secret, loginUrl: url, allowedHosts: hosts,
      ...(flag("sso") ? { ssoHosts: parseHosts(flag("sso"), "--sso") } : {}),
      // Optional username, for login forms that do not pre-fill it. Not a
      // secret — the bridge types it before the password.
      ...(flag("username") ? { username: flag("username") } : {}),
      ...(flag("user-sel") ? { usernameSelector: flag("user-sel") } : {}),
      ...(flag("submit-sel") ? { submitSelector: flag("submit-sel") } : {}),
    });
    await save(doc, pass);
    console.error(`added ${id}`);
  } else if (cmd === "list") {
    // Ids and rules only. There is deliberately no command that prints a secret.
    const doc = await load(await passphrase());
    for (const e of doc.entries) {
      console.log(`credential\t${e.id}\t${e.loginUrl}\t${e.allowedHosts.join(",")}`);
    }
    for (const r of doc.registrations ?? []) {
      console.log(`signup    \t${r.id}\t${r.signupUrl}\t${r.username}`);
    }
    // Capture policies too. `allow-capture` could write one that `list` never
    // showed, so the only way to check what a vault authorises was to decrypt
    // it by hand — for the one policy type that reads a secret off a page.
    for (const c of doc.captures ?? []) {
      console.log(`capture   \t${c.id}\t${c.captureUrl}\t${c.allowedHosts.join(",")}`);
    }
  } else if (cmd === "remove") {
    const id = flag("id");
    if (!id) usage();
    const pass = await passphrase();
    const doc = await load(pass);
    const before = doc.entries.length + doc.registrations.length;
    doc.entries = doc.entries.filter((e) => e.id !== id);
    doc.registrations = doc.registrations.filter((r) => r.id !== id);
    if (doc.entries.length + doc.registrations.length === before) {
      console.error(`${id} not found`); process.exit(1);
    }
    await save(doc, pass);
    console.error(`removed ${id}`);
  } else if (cmd === "allow-signup") {
    // Authorising an agent to create an account. Everything it could otherwise
    // choose is fixed here: the host, the URL, the username, the selectors.
    // The agent supplies only --id.
    const id = flag("id"), signup = flag("signup"), login = flag("login"), username = flag("username");
    if (!id || !signup || !login || !username) usage();
    const hosts = parseHosts(flag("hosts"), "--hosts");
    if (hosts.length === 0) { console.error("--hosts must name at least one host"); process.exit(2); }
    const userSel = flag("user-sel"), passSel = flag("pass-sel");
    if (!userSel || !passSel) { console.error("--user-sel and --pass-sel are required"); process.exit(2); }
    for (const [name, url] of [["--signup", signup], ["--login", login]]) {
      if (!url.startsWith("https://") && !url.startsWith("http://127.0.0.1")) {
        console.error(`${name} must be https (http is allowed only for 127.0.0.1)`);
        process.exit(2);
      }
    }
    const successSel = flag("success-sel"), errorSel = flag("error-sel");
    if (!successSel && !flag("url-changes")) {
      // Without a signal the bridge cannot tell whether the site accepted the
      // password, and it will refuse to commit rather than guess. Say so now,
      // not after someone runs a registration that always reports "rejected".
      console.error("no success signal given; defaulting to --url-changes.");
      console.error("Pass --success-sel for a selector that appears only once the account exists.");
    }
    const pass = await passphrase();
    const doc = await load(pass);
    if (doc.registrations.some((r) => r.id === id)) { console.error(`${id} already allowed`); process.exit(2); }
    doc.registrations.push({
      id, signupUrl: signup, loginUrl: login, username, allowedHosts: hosts,
      usernameSelector: userSel, passwordSelector: passSel,
      ...(flag("submit-sel") ? { submitSelector: flag("submit-sel") } : {}),
      success: {
        ...(successSel ? { selector: successSel } : { urlChanges: true }),
        ...(errorSel ? { errorSelector: errorSel } : {}),
      },
    });
    await save(doc, pass);
    console.error(`allowed signup for ${id} as ${username}`);
  } else if (cmd === "allow-capture") {
    // Authorising an agent to capture a secret the site generates (an API key,
    // a token). Everything it could otherwise choose is fixed here: the page,
    // the control that generates the value, and where the value is read from.
    // The agent supplies only --id and the tab it is logged in on.
    const id = flag("id"), url = flag("url"), login = flag("login");
    if (!id || !url || !login) usage();
    const hosts = parseHosts(flag("hosts"), "--hosts");
    if (hosts.length === 0) { console.error("--hosts must name at least one host"); process.exit(2); }
    const valueSel = flag("value-sel");
    if (!valueSel) { console.error("--value-sel is required (where the secret is read from)"); process.exit(2); }
    for (const [name, u] of [["--url", url], ["--login", login]]) {
      if (!u.startsWith("https://") && !u.startsWith("http://127.0.0.1")) {
        console.error(`${name} must be https (http is allowed only for 127.0.0.1)`);
        process.exit(2);
      }
    }
    const valueProp = flag("value-prop");
    if (valueProp && valueProp !== "value" && valueProp !== "textContent") {
      console.error("--value-prop must be 'value' or 'textContent'"); process.exit(2);
    }
    const pass = await passphrase();
    const doc = await load(pass);
    if (doc.captures.some((c) => c.id === id)) { console.error(`${id} already allowed`); process.exit(2); }
    const entryId = flag("entry-id") || id;
    doc.captures.push({
      id, captureUrl: url, loginUrl: login, allowedHosts: hosts, valueSelector: valueSel,
      ...(flag("generate-sel") ? { generateSelector: flag("generate-sel") } : {}),
      ...(valueProp ? { valueProp } : {}),
      ...(flag("value-attr") ? { valueAttr: flag("value-attr") } : {}),
      ...(flag("entry-id") ? { entryId } : {}),
    });
    await save(doc, pass);
    console.error(`allowed capture for ${id} -> vault id ${entryId}`);
  } else usage();
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
}
