# Security policy

Report vulnerabilities to **security@1claw.co**. Do not open a public issue.

## What this component promises

- A secret fetched for a fill never leaves the bridge process, and never
  appears in a tool result, a log line, or an error message.
- The bridge is the only process attached to Chromium. Agent frameworks connect
  through a CDP **allowlist** proxy — not a response filter, and not a
  denylist, because CDP has ~50 domains and changes every Chromium release.
- Fill safety rules are enforced by the core on every backend. A driver can
  refuse a fill; it cannot widen what is allowed.

## What it does not promise

- Protection from a same-user attacker who can already run code as you. On a
  developer machine the same-user boundary is the weakest link.
- Protection of a secret already in memory from a process debugger.
- That a garbage-collected `SecretHandle` was zeroed. Only `dispose()`,
  `using`, and `use()` guarantee that.
- That a secret never exists as a string anywhere in the process. To type a
  password, the bridge must put those characters into a CDP `Input.*` command,
  and CDP is JSON — so the value transits the pipe to Chromium as text. That is
  inherent to driving a browser and is not something the handle can prevent.
  The invariant `SecretHandle` enforces is narrower and precise: the secret
  never reaches the *agent*, in a tool result, a log line, or an error.
