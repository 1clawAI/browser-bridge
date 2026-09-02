# Contributing

Thanks for looking. This package types passwords into web pages on behalf of
software that is not allowed to see them, so the bar for changes is higher than
its size suggests. That is the whole of why this document exists.

## The invariant

**No backend can return a secret through a tool result.** An agent learns
whether a fill happened, never what was typed.

Most of the code exists to hold that line. If a change makes it easier to get a
credential out of this process — a new tool return shape, a log line, an error
message carrying a value, a `SecretHandle` converted to a string — it will be
declined however useful it is otherwise. `SECURITY.md` sets out what the package
does and does not promise.

## Getting set up

```bash
pnpm install
pnpm test          # 161 tests
pnpm typecheck
```

Node 20.10 or later. `SecretHandle` zeroes its buffer using `Symbol.dispose`,
which Node 18 does not have — on 18 it installs cleanly and silently does not
zero.

## The tests that are not optional

**`adversarial.test.ts`** plays the agent as hostile rather than careless, and
drives `startBridge` — the entry point a real deployment uses. A security-
relevant change must be covered here, not only in a unit test.

Every test in it has been checked by breaking the control it covers and
confirming it goes red. Please do the same for anything you add. This is not
ceremony: in August 2026 the per-file suites passed 121/121 while three controls
did nothing, because every component was individually correct and the bugs were
in the seams. A green suite is evidence about the tests as much as the code.

**`real-chromium.test.ts`** runs against a launched Chromium. Everything else
uses `FakeCdpTransport`, which answers the protocol we *believe* Chromium
speaks — and that belief has been wrong. The fill window was matched on
`params.targetId` for months, a dialect Chromium does not use for the methods
that read a form field, and every test passed because the fake spoke the same
wrong dialect. It skips when no Chromium is found, and says so; set
`ONECLAW_BRIDGE_CHROME` to point at one.

**`core-has-no-driver-conditionals.test.ts`** fails the build if the core ever
names a driver. Drivers own four things: where secrets live, who evaluates
policy, where audit goes, and which capabilities exist. Everything that makes a
fill *safe* — origin and frame checks, TOCTOU generation binding, the CDP fill
window, buffer zeroing, velocity limiting — belongs to the core and behaves
identically on every backend. That split is what makes the invariant reviewable
once instead of once per driver. A driver may refuse a fill; it may never widen
what is allowed.

## Adding a capability

Capabilities gate which MCP tools exist. A backend that returns
`checkout: false` must not implement `authorizeCheckout`, and the adapter must
not register the tool — absent, not disabled. A tool that exists and always
fails teaches an agent to retry, and puts an upsell in agent-visible output.

Add the capability to `CAPABILITY_TOOLS` in the same change that adds it to
`Capabilities`, so deciding what it exposes is a type error rather than an
oversight.

## Pull requests

- One concern per PR. A security fix and a refactor in one diff is a security
  fix nobody can review.
- Say what you broke to prove the test works. "Added a test" and "added a test
  that fails when I remove the check" are different claims.
- Comments should explain *why*, especially where the obvious approach is
  wrong. There is a lot of that in this codebase, and it is deliberate.
- CI runs on Linux, macOS and Windows, plus a secret scan over the full history.
  All four must pass.

## Reporting a vulnerability

Not through an issue or a PR. See `SECURITY.md` — **security@1claw.co**.

If you are unsure whether something is a vulnerability, treat it as one. We
would rather read a report about a non-issue than find out later.
