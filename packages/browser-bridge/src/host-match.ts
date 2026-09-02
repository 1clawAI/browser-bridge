// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * Whether an origin is covered by an allowlist.
 *
 * Shared rather than reimplemented per driver. Two backends already need it and
 * a third would make three subtly different ideas of "allowed" — the shape of
 * defect this codebase keeps producing, and the reason the hosted vault's own
 * policy engine sat unused for a week while a handler re-derived part of it.
 *
 * The rules, and why each one:
 *
 * - **Exact by default.** A bare entry matches only itself. A suffix match
 *   would let `evil-app.example.com` satisfy `app.example.com`, and typing a
 *   credential into a lookalike host is the failure this package exists to
 *   prevent.
 * - **A leading dot opts into subdomains.** `.example.com` matches the apex and
 *   any subdomain. Wildcards are spelled this way because `*` has no meaning
 *   here: an entry the matcher does not understand would be stored, match
 *   nothing, and leave the operator believing a host was allowed.
 * - **Userinfo is stripped explicitly.** `https://app.example.com@evil.test/`
 *   has host `evil.test`. Relying on a URL parser to get that right is a
 *   dependency on someone else's edge cases; taking the last `@` is one line.
 * - **Unparseable denies.** "Not a URL" is not evidence that it is safe.
 */
export function hostAllowed(origin: string, list: readonly string[]): boolean {
  const host = hostOf(origin);
  if (host === undefined) return false;
  return list.some((raw) => {
    const entry = raw.trim().toLowerCase();
    if (entry === "" || entry === ".") return false;
    if (entry.startsWith(".")) {
      const suffix = entry.slice(1);
      return host === suffix || host.endsWith(`.${suffix}`);
    }
    return host === entry;
  });
}

/** The host of an origin, lowercased, or undefined when it cannot be read. */
export function hostOf(value: string): string | undefined {
  if (!value) return undefined;
  const afterScheme = value.includes("://") ? value.slice(value.indexOf("://") + 3) : value;
  const authority = afterScheme.split(/[/?#]/)[0];
  if (authority === undefined || authority === "") return undefined;
  // Last '@', not first: `a@b@evil.test` has host evil.test.
  const at = authority.lastIndexOf("@");
  const hostPort = at >= 0 ? authority.slice(at + 1) : authority;
  const host = hostPort.startsWith("[")
    ? hostPort.slice(1).split("]")[0]
    : hostPort.split(":")[0];
  return host ? host.toLowerCase() : undefined;
}
