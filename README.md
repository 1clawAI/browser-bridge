# 1Claw Browser Bridge

Governed credential fill for AI agents. The agent drives the browser; it never
sees the password.

> **Status: v0.1, private.** The `VaultBackend` trait, `SecretHandle` and the
> saas driver are in. The CDP allowlist proxy, MCP surface and community driver
> are not yet — see [Roadmap](#roadmap). This repository goes public only after
> the adversarial suite is green on every shipped driver.

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
  drivers/saas.ts   1Claw-hosted backend
```

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

The suite includes mutation-verified guards: making `toJSON` return plaintext,
removing the buffer zeroing, or adding `if (backend === "saas")` to the core
each fail a specific test.

## Roadmap

- **v0.1** (here) — `VaultBackend` + `SecretHandle` + saas driver → CDP allowlist proxy, MCP stdio, vault handlers
- **OSS launch** — community driver, form action + fingerprint checks, adversarial harness, mock-vault
- **v0.2** — governed credential registration, HITL approval queue, TOTP fill
- **v0.3** — cloud-runtime sidecar (platform trust model)

## Security

The threat model, the CDP ownership argument and the adversarial test matrix
live in the 1Claw browser-bridge spec. Report vulnerabilities to
security@1claw.co rather than opening an issue.

Apache-2.0.
