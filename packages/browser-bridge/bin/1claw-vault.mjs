#!/usr/bin/env node
// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * Manage a local encrypted vault for the browser bridge.
 *
 *   1claw-vault init   <file>
 *   1claw-vault add    <file> --id <id> --url <login-url> --hosts a.com,.b.com
 *   1claw-vault list   <file>
 *   1claw-vault remove <file> --id <id>
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

const [cmd, file, ...rest] = process.argv.slice(2);
const flag = (n) => { const i = rest.indexOf(`--${n}`); return i > -1 ? rest[i + 1] : undefined; };

function usage(code = 2) {
  console.error(`usage:
  1claw-vault init   <file>
  1claw-vault add    <file> --id <id> --url <login-url> --hosts a.com,.b.com [--sso idp.com]
  1claw-vault list   <file>
  1claw-vault remove <file> --id <id>

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
  return openVault(JSON.parse(await readFile(file, "utf8")), pass);
}
async function save(entries, pass) {
  // 0600: a vault the rest of the machine can read is not a vault.
  await writeFile(file, JSON.stringify(await sealVault(entries, pass), null, 2), { mode: 0o600 });
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
    await save([], pass);
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
    const entries = await load(pass);
    if (entries.some((e) => e.id === id)) { console.error(`${id} already exists`); process.exit(2); }
    const secret = await readStdin();
    if (!secret) { console.error("empty secret"); process.exit(2); }
    entries.push({ id, secret, loginUrl: url, allowedHosts: hosts, ...(flag("sso") ? { ssoHosts: parseHosts(flag("sso"), "--sso") } : {}) });
    await save(entries, pass);
    console.error(`added ${id}`);
  } else if (cmd === "list") {
    // Ids and rules only. There is deliberately no command that prints a secret.
    for (const e of await load(await passphrase())) {
      console.log(`${e.id}\t${e.loginUrl}\t${e.allowedHosts.join(",")}`);
    }
  } else if (cmd === "remove") {
    const id = flag("id");
    if (!id) usage();
    const pass = await passphrase();
    const entries = await load(pass);
    const left = entries.filter((e) => e.id !== id);
    if (left.length === entries.length) { console.error(`${id} not found`); process.exit(1); }
    await save(left, pass);
    console.error(`removed ${id}`);
  } else usage();
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
}
