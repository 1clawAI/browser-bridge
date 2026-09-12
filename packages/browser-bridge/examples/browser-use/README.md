# browser-use, end to end

Proves browser-use (a Python agentic browser framework, not built on Puppeteer
or Playwright) connects to the bridge the same way `puppeteer-core` and
`playwright-core` already do — and that the credential-fill guarantee holds
when browser-use is the one driving the page.

Two processes, because that is what actually talks to the bridge here:
`bridge_server.mjs` (Node) starts a real bridge and a tiny login site;
`test_login.py` (Python) connects browser-use to it, drives the page, and
requests a fill.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install browser-use
```

## Run

From the repo root:

```bash
pnpm install && pnpm build
```

Then, from this directory:

```bash
source .venv/bin/activate
python3 test_login.py
```

Expect:

```
browser-use connected through the bridge's CDP proxy: OK
agent's target_id (this is what gets windowed during the fill): ...
agent's tab, read live via browser-use's own CDP session: http://127.0.0.1:.../login

fill result (this, and only this, is what browser-use as the agent would receive): {'status': 'filled', 'bindingId': 'example-login'}
agent's own tab, navigated to /welcome after the fill, reads: 'Welcome, ada@example.com'

=== RESULT ===
stock browser-use connects through the bridge:       yes
fill reported status:                                 filled
login actually succeeded (agent's tab sees /welcome): True
password ever visible to browser-use:                 no
```

## What this actually checks

1. **Connectivity.** `BrowserProfile(cdp_url=bridge.url, is_local=True)` — the
   `ws://` URL `startBridge` prints, unchanged. browser-use's own
   `connect()` skips its usual `/json/version` HTTP discovery whenever
   `cdp_url` already starts with `ws`, so it goes straight to the WebSocket —
   the same shape Puppeteer's `browserWSEndpoint` and Playwright's
   `connectOverCDP` use, both proven in `framework-connect.test.ts`. No
   special-casing was needed on the bridge side for this to work.
2. **The gate still refuses what it should.** browser-use calls
   `Browser.grantPermissions` on connect, which Puppeteer and Playwright
   don't — the bridge correctly refuses it (`method_not_allowed`, not on the
   allowlist) and browser-use handles the refusal without breaking the
   session.
3. **The actual product claim.** browser-use's own tab never touches the
   password field. The fill happens on a throwaway target the bridge creates
   itself. Afterward, browser-use's *same* tab — having typed nothing — loads
   a cookie-gated page and gets the authenticated view, proving the session
   really landed in the shared browser context. The password never appears in
   the fill result or in anything browser-use reads back.

One browser-use quirk surfaced along the way, unrelated to the bridge: right
after `navigate_to()`, browser-use's own `get_tabs()`/`tab.url` cache can
still say `about:blank` even though the page really navigated (confirmed by
reading `location.href` directly through browser-use's own CDP session
instead of trusting its tab cache). Worth knowing if you build on this
further; not something this example works around, since it doesn't affect the
result.
