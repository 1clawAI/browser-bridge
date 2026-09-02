// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { CdpGate, redactEventForAgent } from "./cdp-policy.js";

const TARGET = "target-1";
const OTHER = "target-2";

describe("CDP fill window", () => {
  // From the plan's matrix: "Any agent CDP command on fill target during window
  // → fill_in_progress; MCP status poll works".
  it("blocks every command on the fill target while a fill is open", () => {
    const gate = new CdpGate();
    gate.openFillWindow(TARGET);
    for (const method of [
      "Runtime.evaluate",
      "DOM.getDocument",
      "Page.captureScreenshot",
      "Accessibility.getFullAXTree",
      "Input.dispatchKeyEvent",
    ]) {
      const d = gate.evaluateCommand({ method, targetId: TARGET });
      expect(d.allow, `${method} should be blocked`).toBe(false);
      if (!d.allow) expect(d.reason).toBe("fill_in_progress");
    }
  });

  // The whole target, not just the field: a partial block leaves
  // `btoa(input.value)` and char-code transforms wide open, and neither returns
  // the value in a form a response filter would recognise.
  it("blocks the transform bypasses a response filter would miss", () => {
    const gate = new CdpGate();
    gate.openFillWindow(TARGET);
    const d = gate.evaluateCommand({
      method: "Runtime.evaluate",
      targetId: TARGET,
      params: { expression: "btoa(document.querySelector('input[type=password]').value)" },
    });
    expect(d.allow).toBe(false);
  });

  it("leaves other targets usable, so one fill does not freeze the agent", () => {
    const gate = new CdpGate();
    gate.openFillWindow(TARGET);
    expect(gate.evaluateCommand({ method: "DOM.getDocument", targetId: OTHER }).allow).toBe(true);
  });

  it("reopens the target once the window closes", () => {
    const gate = new CdpGate();
    gate.openFillWindow(TARGET);
    gate.closeFillWindow(TARGET);
    expect(gate.evaluateCommand({ method: "DOM.getDocument", targetId: TARGET }).allow).toBe(true);
  });
});

describe("request and response bodies", () => {
  // "getRequestPostData post-window: login POST requestId from fill window →
  // refused permanently." Wholesale denial makes the timing irrelevant.
  it("refuses body access always — during a fill and long after", () => {
    const gate = new CdpGate();
    for (const method of [
      "Network.getRequestPostData",
      "Network.getResponseBody",
      "Fetch.enable",
      "Network.takeResponseBodyForInterceptionAsStream",
    ]) {
      const before = gate.evaluateCommand({ method, targetId: TARGET });
      expect(before.allow, `${method} before any fill`).toBe(false);
      if (!before.allow) expect(before.reason).toBe("body_access_denied");
    }
    gate.openFillWindow(TARGET);
    gate.closeFillWindow(TARGET);
    expect(gate.evaluateCommand({ method: "Network.getRequestPostData", targetId: TARGET }).allow).toBe(false);
  });

  it("refuses the debugger and heap snapshots, which read what was typed", () => {
    const gate = new CdpGate();
    for (const method of ["Debugger.enable", "Debugger.pause", "HeapProfiler.takeHeapSnapshot"]) {
      expect(gate.evaluateCommand({ method, targetId: TARGET }).allow, method).toBe(false);
    }
  });

  it("refuses re-attachment routes that would bypass the gate entirely", () => {
    const gate = new CdpGate();
    for (const method of ["Target.setAutoAttach", "Target.createBrowserContext", "Browser.close"]) {
      expect(gate.evaluateCommand({ method, targetId: TARGET }).allow, method).toBe(false);
    }
  });
});

describe("allowlist, not denylist", () => {
  // CDP gains domains every Chromium release. An unknown method must be refused
  // by default, or each release silently widens what an agent can do.
  it("refuses a method it has never heard of", () => {
    const gate = new CdpGate();
    const d = gate.evaluateCommand({ method: "SomeFuture.newCapability", targetId: TARGET });
    expect(d.allow).toBe(false);
    if (!d.allow) expect(d.reason).toBe("method_not_allowed");
  });

  it("still allows the ordinary driving an agent needs", () => {
    const gate = new CdpGate();
    for (const method of ["Page.navigate", "DOM.querySelector", "Runtime.evaluate", "Input.dispatchMouseEvent"]) {
      expect(gate.evaluateCommand({ method, targetId: TARGET }).allow, method).toBe(true);
    }
  });
});

describe("event suppression", () => {
  // "Pre-enabled Network domain: requestWillBeSent with postData → suppressed,
  // not delivered; not replayed after window."
  it("suppresses events on a filling target, including a pre-enabled Network domain", () => {
    const gate = new CdpGate();
    gate.openFillWindow(TARGET);
    expect(
      gate.shouldForwardEvent({
        method: "Network.requestWillBeSent",
        targetId: TARGET,
        params: { request: { postData: "username=a&password=hunter2" } },
      }),
    ).toBe(false);
  });

  it("drops suppressed events rather than queueing them for replay", () => {
    const gate = new CdpGate();
    gate.openFillWindow(TARGET);
    const evt = { method: "Network.requestWillBeSent", targetId: TARGET };
    expect(gate.shouldForwardEvent(evt)).toBe(false);
    gate.closeFillWindow(TARGET);
    // The gate holds no buffer to replay from; the only thing that could
    // resurface the event is a queue, and there is none.
    expect(Object.keys(gate)).toEqual([]);
  });

  it("strips the cookies out of the extra-info events rather than withholding them", () => {
    // These two were refused outright, for the right reason: they carry the
    // raw `Cookie` and `Set-Cookie` headers, and they are push events, so an
    // agent that enabled the Network domain before a fill would receive them
    // without issuing a single command during the window.
    //
    // Refusing them also broke every stock client. A framework will not settle
    // a navigation until its network bookkeeping sees the ExtraInfo pair, so
    // `page.goto()` hung while `page.content()` returned the new document.
    //
    // What a client needs is that the event happened. What it must not have is
    // the headers. So they are forwarded emptied — and emptied, not deleted,
    // because a client reads `Object.keys(headers)` without checking the field
    // is there, and removing it crashes the client instead of protecting
    // anything.
    for (const method of [
      "Network.requestWillBeSentExtraInfo",
      "Network.responseReceivedExtraInfo",
    ]) {
      // The field set Chromium actually sends, read off a live browser rather
      // than from the protocol docs — that is how `blockedCookies` was found
      // missing from the strip list, and `rawHeaders`, which is in the docs,
      // found never to be sent at all.
      const out = redactEventForAgent(method, {
        requestId: "req-1",
        headers: { cookie: "sid=hunter2", authorization: "Bearer tok" },
        headersText: "set-cookie: sid=hunter2",
        associatedCookies: [{ cookie: { name: "sid", value: "hunter2" }, blockedReasons: [] }],
        blockedCookies: [{ cookie: { name: "sid", value: "hunter2" }, blockedReasons: ["x"] }],
        exemptedCookies: [{ cookie: { name: "sid", value: "hunter2" } }],
        statusCode: 200,
      });

      const serialised = JSON.stringify(out);
      expect(serialised, `${method} leaked a credential`).not.toContain("hunter2");
      expect(serialised).not.toContain("Bearer tok");
      // The shape survives, so the client's state machine still advances.
      expect((out as { requestId?: string }).requestId).toBe("req-1");
      // Fields that carry no credential material survive untouched, so the
      // client still has what it needs to match the event to its request.
      if (method === "Network.responseReceivedExtraInfo") {
        expect((out as { statusCode?: number }).statusCode).toBe(200);
      }
      expect(out).toHaveProperty("headers");
      expect(Object.keys((out as { headers: object }).headers)).toHaveLength(0);
      expect((out as { associatedCookies: unknown[] }).associatedCookies).toEqual([]);
    }
  });

  it("leaves events it does not redact exactly as they came", () => {
    const evt = { requestId: "r", headers: { cookie: "keep-me" } };
    expect(redactEventForAgent("Network.responseReceived", evt)).toBe(evt);
  });

  it("still refuses the events that carry a body outright", () => {
    const gate = new CdpGate();
    for (const method of ["Debugger.paused", "Debugger.scriptParsed"]) {
      expect(gate.shouldForwardEvent({ method, targetId: OTHER }), method).toBe(false);
    }
  });

  it("forwards ordinary events on targets that are not filling", () => {
    const gate = new CdpGate();
    gate.openFillWindow(TARGET);
    expect(gate.shouldForwardEvent({ method: "Page.loadEventFired", targetId: OTHER })).toBe(true);
  });
});
