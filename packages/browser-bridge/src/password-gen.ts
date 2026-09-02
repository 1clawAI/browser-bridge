// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { randomInt } from "node:crypto";

/**
 * What a site demands of a password.
 *
 * Human-authored, per site, because there is no way to discover it reliably:
 * rules are undocumented, enforced inconsistently between the client and the
 * server, and often only revealed by a rejection. Guessing them is how a
 * registration ends up committing a password the site never accepted.
 */
export type PasswordPolicy = {
  readonly length?: number;
  readonly lower?: boolean;
  readonly upper?: boolean;
  readonly digits?: boolean;
  /** Symbols to draw from. Empty or absent means the site forbids them. */
  readonly symbols?: string;
};

const LOWER = "abcdefghijkmnopqrstuvwxyz"; // no l
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I, O
const DIGITS = "23456789"; // no 0, 1
const DEFAULT_SYMBOLS = "!@#$%^&*-_=+";

export const DEFAULT_PASSWORD_POLICY: Required<Omit<PasswordPolicy, "symbols">> & {
  symbols: string;
} = {
  length: 24,
  lower: true,
  upper: true,
  digits: true,
  symbols: DEFAULT_SYMBOLS,
};

/**
 * Generate a password that satisfies `policy`.
 *
 * Uniform over the alphabet via `randomInt`, which rejects modulo bias rather
 * than folding it in — `bytes[i] % n` skews toward the low end of the alphabet,
 * which is exactly the kind of quiet weakness nobody notices in a generated
 * secret.
 *
 * One character of each required class is placed first and the result shuffled,
 * so a policy is satisfied by construction rather than by retrying until the
 * random draw happens to comply. Retrying would be correct too, but its running
 * time depends on the policy and it is easy to write a loop that never
 * terminates for a policy nothing can satisfy.
 *
 * Confusable characters are excluded throughout — `l`, `I`, `O`, `0`, `1`.
 * These get read aloud, transcribed, and typed by hand during account recovery.
 */
export function generatePassword(policy: PasswordPolicy = {}): string {
  const p = { ...DEFAULT_PASSWORD_POLICY, ...policy };
  const classes: string[] = [];
  if (p.lower) classes.push(LOWER);
  if (p.upper) classes.push(UPPER);
  if (p.digits) classes.push(DIGITS);
  if (p.symbols && p.symbols.length > 0) classes.push(p.symbols);

  if (classes.length === 0) {
    throw new Error("password policy permits no characters at all");
  }
  if (p.length < classes.length) {
    throw new Error(
      `length ${p.length} cannot satisfy ${classes.length} required character classes`,
    );
  }
  if (p.length < 8) {
    // A short password is the weakness the rest of this package cannot make up
    // for. If a site demands one, that is worth a human noticing.
    throw new Error("refusing to generate a password shorter than 8 characters");
  }

  const alphabet = classes.join("");
  const chars: string[] = classes.map((c) => c[randomInt(c.length)]!);
  while (chars.length < p.length) chars.push(alphabet[randomInt(alphabet.length)]!);

  // Fisher-Yates, so the guaranteed characters are not always at the front.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
  return chars.join("");
}

/** Does `value` satisfy `policy`? Used to check a site's own suggestion. */
export function satisfies(value: string, policy: PasswordPolicy = {}): boolean {
  const p = { ...DEFAULT_PASSWORD_POLICY, ...policy };
  if (value.length < p.length) return false;
  if (p.lower && !/[a-z]/.test(value)) return false;
  if (p.upper && !/[A-Z]/.test(value)) return false;
  if (p.digits && !/[0-9]/.test(value)) return false;
  if (p.symbols && p.symbols.length > 0) {
    const set = new Set(p.symbols.split(""));
    if (![...value].some((c) => set.has(c))) return false;
  }
  return true;
}
