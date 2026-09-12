#!/usr/bin/env python3
"""
Does browser-use (github.com/browser-use/browser-use), a real third-party
agentic browser framework, work against browser-bridge's CDP proxy the same
way Puppeteer and Playwright already do -- and does the credential-fill
guarantee still hold when browser-use is the one driving the page?

Starts a companion Node process (bridge_server.mjs) that runs a real bridge +
a tiny login site, connects browser-use directly to the bridge's ws:// URL,
drives the page normally, then asks the bridge (via the Node side) to fill
the password.

The ws:// URL matters: browser-use's BrowserSession.connect() normally treats
`cdp_url` as an http(s) endpoint and fetches /json/version from it to find the
real WebSocket URL -- a discovery step browser-bridge does not serve (plain
HTTP gets a flat 404; the only surface is the WebSocket upgrade, by design).
But browser-use's own connect() checks `if not self.cdp_url.startswith('ws')`
before doing that fetch, so handing it the ws:// URL the bridge already prints
skips discovery entirely -- no special-casing needed on either side. This is
the same shape as Puppeteer's `browserWSEndpoint` and Playwright's
`connectOverCDP`, both proven in framework-connect.test.ts; this file is the
same proof for browser-use.

Success is: the fill reports "filled", browser-use's own tab (never having
typed anything) is authenticated afterward, and PASSWORD never appears in
anything browser-use itself received -- the fill result or the page it reads.

Setup:
    python3 -m venv .venv && source .venv/bin/activate
    pip install browser-use

Run (from this directory, after `pnpm build` at the repo root):
    python3 test_login.py
"""
import asyncio
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PASSWORD = "correct-horse-battery-staple-bu"


async def main():
    node = subprocess.Popen(
        ["node", os.path.join(HERE, "bridge_server.mjs")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

    bridge_url = site_url = None
    for _ in range(50):
        line = node.stdout.readline()
        if not line:
            raise RuntimeError("bridge server exited before READY")
        line = line.strip()
        print(f"[node] {line}")
        if line.startswith("BRIDGE_URL="):
            bridge_url = line.split("=", 1)[1]
        elif line.startswith("SITE_URL="):
            site_url = line.split("=", 1)[1]
        elif line == "READY":
            break
    if not (bridge_url and site_url):
        raise RuntimeError("did not get BRIDGE_URL/SITE_URL from bridge_server.mjs")

    print(f"\nbridge: {bridge_url}")
    print(f"site:   {site_url}\n")

    from browser_use.browser.profile import BrowserProfile
    from browser_use.browser.session import BrowserSession

    session = BrowserSession(browser_profile=BrowserProfile(cdp_url=bridge_url, is_local=True))

    leaked = False
    try:
        # 1) Stock-framework connectivity: same claim framework-connect.test.ts
        #    proves for puppeteer-core/playwright-core, now for browser-use's
        #    own CDP client (cdp_use, not Playwright, despite older browser-use
        #    releases having been Playwright-based).
        await session.start()
        print("browser-use connected through the bridge's CDP proxy: OK")

        await session.navigate_to(site_url)
        tabs = await session.get_tabs()
        assert tabs, "browser-use opened no tab"
        target_id = tabs[-1].target_id
        print(f"agent's target_id (this is what gets windowed during the fill): {target_id}")

        # browser-use's own get_tabs()/tab.url cache can stay stale at
        # "about:blank" right after navigate_to() even though the page really
        # did navigate -- a browser-use-internal quirk, not a bridge one.
        # Reading location.href directly through browser-use's own CDP
        # session (rather than trusting its tab cache) confirms the real state.
        cdp_session = await session.get_or_create_cdp_session(target_id=target_id, focus=False)
        href = await cdp_session.cdp_client.send.Runtime.evaluate(
            params={"expression": "location.href", "returnByValue": True}, session_id=cdp_session.session_id,
        )
        print(f"agent's tab, read live via browser-use's own CDP session: {(href.get('result') or {}).get('value')}\n")

        # 2) The actual product claim: request a fill on browser-use's own
        #    tab, without browser-use itself ever touching the password field.
        node.stdin.write(f"FILL {target_id}\n")
        node.stdin.flush()
        result_line = ""
        for _ in range(50):
            l = node.stdout.readline().strip()
            print(f"[node] {l}")
            if l.startswith("FILL_RESULT="):
                result_line = l.split("=", 1)[1]
                break
        result = json.loads(result_line) if result_line else {}
        print(f"\nfill result (this, and only this, is what browser-use as the agent would receive): {result}")
        if PASSWORD in json.dumps(result):
            leaked = True
            print("PASSWORD FOUND IN FILL RESULT -- BUG")

        # 3) Prove the login actually took. The fill happens on a throwaway
        #    target the bridge creates itself, never the agent's own tab, so
        #    seeing this requires the agent to independently load a page that
        #    reflects the resulting session -- exactly what a real agent would
        #    do next, and exactly what register-login-act.mjs's /account
        #    endpoint proves for the Puppeteer examples. bridge_server.mjs's
        #    /welcome only renders the authenticated view when the session
        #    cookie is present, so this is a genuine check that the cookie
        #    landed in the shared browser context, not a page that renders
        #    the same text regardless.
        welcome_url = site_url.replace("/login", "/welcome")
        await cdp_session.cdp_client.send.Page.navigate(
            params={"url": welcome_url}, session_id=cdp_session.session_id,
        )
        await asyncio.sleep(0.5)
        page_text = await cdp_session.cdp_client.send.Runtime.evaluate(
            params={"expression": "document.body.innerText", "returnByValue": True},
            session_id=cdp_session.session_id,
        )
        body_text = (page_text.get("result") or {}).get("value", "")
        print(f"agent's own tab, navigated to /welcome after the fill, reads: {body_text!r}")
        if PASSWORD in body_text:
            leaked = True
            print("PASSWORD FOUND IN THE PAGE BROWSER-USE CAN READ -- BUG")
        logged_in = "Welcome" in body_text and "ada@example.com" in body_text

        print("\n=== RESULT ===")
        print("stock browser-use connects through the bridge:       yes")
        print(f"fill reported status:                                 {result.get('status')}")
        print(f"login actually succeeded (agent's tab sees /welcome): {logged_in}")
        print(f"password ever visible to browser-use:                 {'YES -- BUG' if leaked else 'no'}")
        sys.exit(1 if (leaked or result.get("status") != "filled" or not logged_in) else 0)
    finally:
        try:
            await session.stop()
        except Exception as e:
            print(f"(session.stop() error, non-fatal for this example: {e})")
        node.stdin.write("STOP\n")
        node.stdin.flush()
        try:
            node.wait(timeout=10)
        except Exception:
            node.kill()


if __name__ == "__main__":
    asyncio.run(main())
