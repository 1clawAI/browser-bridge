# Examples

Runnable end to end, no account and no network. Each launches a real Chromium
over a pipe, so it needs a Chromium binary. Point at one with `--chrome`, or set
`ONECLAW_BRIDGE_CHROME`; on macOS and Linux the usual path is the default.

```bash
pnpm install && pnpm build
node packages/browser-bridge/examples/demo.mjs
node packages/browser-bridge/examples/register-login-act.mjs
```

| File | What it shows |
| --- | --- |
| `demo.mjs` | A fill happens and the agent's tool result is printed, so you can check the password is not in it. An off-host fill is denied. |
| `register-login-act.mjs` | The whole flow: the bridge signs up (generating the password), stores it encrypted, fills and submits a login so the **agent's own tab** ends up authenticated, and the agent then updates a profile as that user. The password is in none of it. |
| `agent.mjs` | The minimal CDP client the two above use to stand in for a framework. Not a demo on its own. |

`register-login-act.mjs` prints each step:

```
  1. register          -> {"status":"registered","bindingId":"acme"}
     password stored, 24-char, encrypted in the vault (cleartext in file: no)
  2. agent self-context -> refused (good)
  3. before login       -> anonymous
  4. login fill         -> {"status":"filled","bindingId":"acme"}
  5. after login        -> ada@example.com
  6. update profile     -> HTTP 200, server recorded ["Ada Lovelace"]

  agent ever saw the password: no
```

## Connecting a framework

These examples connect through the bridge's CDP proxy with a small hand-rolled
client (`agent.mjs`). That is deliberate, and worth being clear about, because
the more obvious choice does not work yet.

**Puppeteer and Playwright do not connect through the gate as of v0.1**, and
neither do the Playwright-based agents built on them (browser-use, Stagehand).
On attach they call `Browser.getVersion`, which is not on the allowlist:

```
Protocol error (Browser.getVersion): method_not_allowed:
  Browser.getVersion is not on the bridge allowlist
```

Allowlisting that one method is not enough on its own — those clients also drive
target discovery with `Target.setAutoAttach` and `Target.setDiscoverTargets`,
which the gate refuses **by design**: re-attaching to Chromium outside the gate
is the one step that makes the whole no-plaintext invariant moot (see
`cdp-policy.ts`). Supporting a stock framework client therefore means teaching
the proxy to answer that handshake itself rather than passing it through, which
is a real change to the proxy and not a line in the allowlist.

Until then, a framework integrates the way `agent.mjs` does: speak gated CDP
directly, using the allowlisted methods (`Target.createTarget`,
`Target.attachToTarget`, `Page.navigate`, `Page.reload`, `Runtime.evaluate`,
`Input.*`), and call the MCP tools (`request_fill`,
`begin_credential_registration`) for anything that touches a credential. The
tools return a status, never a secret.
