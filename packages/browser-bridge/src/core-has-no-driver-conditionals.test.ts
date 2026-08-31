// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = dirname(fileURLToPath(import.meta.url));
const DRIVERS = join(SRC, "drivers");

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const p = join(dir, entry);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

/** Core = everything that is not a driver and not a test. */
const coreFiles = walk(SRC).filter(
  (f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && !f.startsWith(DRIVERS),
);

/**
 * The security invariant is reviewable exactly once — in the core — only if the
 * core cannot tell which backend it is talking to.
 *
 * The moment `if (backend === "saas")` appears, the fill rules fork, and every
 * future reader has to verify each branch separately. The plan makes "core has
 * zero driver-conditionals" a v0.1 gate; this is that gate, enforced rather
 * than remembered.
 */
describe("core has no driver conditionals", () => {
  const DRIVER_NAMES = ["saas", "community", "local-vault", "localvault", "mock-vault"];

  it("finds core files to check (guards against the glob silently matching nothing)", () => {
    expect(coreFiles.length).toBeGreaterThan(0);
  });

  it.each(DRIVER_NAMES)("never branches on %s", (name) => {
    const offenders: string[] = [];
    for (const file of coreFiles) {
      for (const [i, line] of readFileSync(file, "utf8").split("\n").entries()) {
        // Comments are how the split is explained, so they are allowed to name
        // drivers; code is not.
        const code = line.replace(/\/\/.*$/, "").replace(/\/\*.*?\*\//g, "");
        if (new RegExp(`["'\`]${name}["'\`]`, "i").test(code)) {
          offenders.push(`${relative(SRC, file)}:${i + 1}: ${line.trim()}`);
        }
      }
    }
    expect(offenders, `core must not name drivers:\n${offenders.join("\n")}`).toEqual([]);
  });

  it("keeps drivers out of the core's import graph", () => {
    const offenders = coreFiles
      .filter((f) => /from\s+["'].*\/drivers\//.test(readFileSync(f, "utf8")))
      .map((f) => relative(SRC, f));
    // index.ts re-exports drivers for consumers; it holds no fill logic.
    expect(offenders.filter((f) => f !== "index.ts")).toEqual([]);
  });
});

/**
 * A grep for plaintext handling in the core. Cheap, and it catches the shape of
 * mistake that undoes SecretHandle: turning the bytes back into a string and
 * passing that around.
 */
describe("core does not stringify secrets", () => {
  it("never decodes a secret buffer into a string outside SecretHandle", () => {
    const offenders: string[] = [];
    for (const file of coreFiles) {
      if (file.endsWith("secret-handle.ts")) continue;
      const src = readFileSync(file, "utf8");
      for (const [i, line] of src.split("\n").entries()) {
        const code = line.replace(/\/\/.*$/, "");
        if (/TextDecoder\(\)\.decode|\.toString\(["']utf-?8["']\)/.test(code)) {
          offenders.push(`${relative(SRC, file)}:${i + 1}: ${line.trim()}`);
        }
      }
    }
    expect(offenders, `decode a secret only inside a use()/peek() callback:\n${offenders.join("\n")}`).toEqual([]);
  });
});
