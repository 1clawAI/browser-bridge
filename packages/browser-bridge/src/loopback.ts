// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * Who may talk to the bridge's local listeners.
 *
 * Both the optional HTTP MCP surface and the CDP proxy WebSocket live on
 * 127.0.0.1, and "it is only on loopback" is not a boundary: every page in the
 * browser the bridge is driving can reach 127.0.0.1 too. A page that opens
 * `new WebSocket('ws://127.0.0.1:9222/…')` would otherwise get an agent-grade
 * CDP session from inside the very browser being protected.
 *
 * Three checks, each covering a hole the others do not:
 *
 *   - **Any `Origin` header is rejected.** Not merely cross-site ones. A
 *     `fetch()` from a page always sends `Origin`; the bridge's own clients
 *     (stdio, or a local process) never do. Filtering on
 *     `Sec-Fetch-Site: cross-site` misses the case that matters, because
 *     localhost-to-localhost is *same*-site and a page on 127.0.0.1 would pass.
 *   - **Host must be a literal loopback address.** DNS rebinding turns an
 *     attacker-controlled name into 127.0.0.1 after the page has loaded; the
 *     request then arrives with `Host: evil.example`, which is the tell.
 *   - **A per-session token in the path.** Ambient authority is what makes the
 *     other two load-bearing; with a token, a guessed URL is not enough.
 */

export type LoopbackCheck =
  | { readonly ok: true }
  | { readonly ok: false; readonly status: 403 | 404; readonly reason: string };

const OK: LoopbackCheck = { ok: true };

const reject = (status: 403 | 404, reason: string): LoopbackCheck => ({ ok: false, status, reason });

/** Hosts that are genuinely this machine. Anything else is a rebinding attempt. */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1"]);

function hostWithoutPort(host: string): string {
  // IPv6 literals are bracketed, so a naive split on ":" mangles them.
  if (host.startsWith("[")) {
    const end = host.indexOf("]");
    return end === -1 ? host : host.slice(0, end + 1);
  }
  const colon = host.indexOf(":");
  return colon === -1 ? host : host.slice(0, colon);
}

export type LoopbackRequest = {
  readonly headers: Readonly<Record<string, string | undefined>>;
  /** Request path, which carries the session token. */
  readonly path: string;
};

/**
 * Decide whether a request to a local listener may proceed.
 *
 * `expectedToken` is the per-session token minted at bridge start. A mismatch
 * is a 404 rather than a 403: a wrong token should not confirm that a listener
 * is here at all.
 */
export function checkLoopbackRequest(req: LoopbackRequest, expectedToken: string): LoopbackCheck {
  // Any Origin at all means a browser sent this, and no legitimate client is a
  // browser page.
  const origin = req.headers.origin ?? req.headers.Origin;
  if (origin !== undefined && origin !== "") {
    return reject(403, "requests carrying an Origin header come from a page, not a bridge client");
  }

  const rawHost = req.headers.host ?? req.headers.Host;
  if (!rawHost) return reject(403, "missing Host header");
  if (!LOOPBACK_HOSTS.has(hostWithoutPort(rawHost))) {
    return reject(403, `Host ${rawHost} is not a loopback literal (possible DNS rebinding)`);
  }

  if (!expectedToken) return reject(403, "bridge has no session token configured");
  const supplied = req.path.split("/").filter(Boolean).at(-1) ?? "";
  if (!timingSafeEqual(supplied, expectedToken)) {
    return reject(404, "unknown endpoint");
  }

  return OK;
}

/**
 * Constant-time comparison. The token is a bearer secret, and a length-varying
 * or early-exit compare leaks it a character at a time to a local attacker who
 * can time requests.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
