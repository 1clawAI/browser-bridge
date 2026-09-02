// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { CdpProxy } from "./cdp-proxy.js";
import { FakeCdpTransport, type CdpMessage } from "./cdp-transport.js";

/**
 * The framework attach handshake, answered by the proxy.
 *
 * Puppeteer and Playwright could not connect at all: `Browser.getVersion` was
 * not allowlisted, and the discovery commands they follow it with are in
 * NEVER_ALLOWED — correctly, because forwarding them puts Chromium into a mode
 * where it reports every target to whoever asked.
 *
 * Answering them locally is only safe if nothing synthesised here ever names a
 * target the asking client does not own. That is what these tests hold, and it
 * is the property a leak would break: a discovery reply naming somebody else's
 * page is a way back to an ungated target.
 */
function proxyWithTwoClients() {
  const transport = new FakeCdpTransport();
  const proxy = new CdpProxy(transport);
  const a: CdpMessage[] = [];
  const b: CdpMessage[] = [];
  proxy.register("client-a", "ctx-a", (e) => a.push(e));
  proxy.register("client-b", "ctx-b", (e) => b.push(e));
  return { proxy, transport, a, b };
}

describe("the attach handshake", () => {
  it("answers Browser.getVersion, which both clients send first", async () => {
    const { proxy } = proxyWithTwoClients();
    const reply = await proxy.handleCommand("client-a", { id: 1, method: "Browser.getVersion" });
    expect(reply.kind).toBe("forward");
    expect(reply.message.error, "this is the error that stopped both frameworks").toBeUndefined();
    expect(reply.message.id).toBe(1);
  });

  it("still refuses the command that would leak the launch flags", async () => {
    // getVersion is version strings. getBrowserCommandLine includes
    // --user-data-dir and everything else the bridge launched with.
    const { proxy } = proxyWithTwoClients();
    const reply = await proxy.handleCommand("client-a", {
      id: 2,
      method: "Browser.getBrowserCommandLine",
    });
    expect(reply.message.error).toBeTruthy();
  });

  it("accepts discovery without putting Chromium into global discovery", async () => {
    const { proxy, transport } = proxyWithTwoClients();
    const before = transport.sent.length;
    const reply = await proxy.handleCommand("client-a", {
      id: 3,
      method: "Target.setDiscoverTargets",
      params: { discover: true },
    });
    expect(reply.message.error).toBeUndefined();
    // Nothing was forwarded: Chromium never learns anyone wants discovery.
    expect(transport.sent.slice(before).map((m) => m.method)).not.toContain(
      "Target.setDiscoverTargets",
    );
  });

  it("accepts auto-attach without forwarding it either", async () => {
    const { proxy, transport } = proxyWithTwoClients();
    const before = transport.sent.length;
    const reply = await proxy.handleCommand("client-a", {
      id: 4,
      method: "Target.setAutoAttach",
      params: { autoAttach: true, flatten: true, waitForDebuggerOnStart: false },
    });
    expect(reply.message.error).toBeUndefined();
    expect(transport.sent.slice(before).map((m) => m.method)).not.toContain("Target.setAutoAttach");
  });
});

describe("what a discovering client is told about", () => {
  it("sees its own page appear", async () => {
    const { proxy, a } = proxyWithTwoClients();
    await proxy.handleCommand("client-a", {
      id: 1,
      method: "Target.setDiscoverTargets",
      params: { discover: true },
    });
    await proxy.handleCommand("client-a", {
      id: 2,
      method: "Target.createTarget",
      params: { url: "https://example.com" },
    });
    const created = a.filter((e) => e.method === "Target.targetCreated");
    expect(created).toHaveLength(1);
    expect((created[0]!.params as never as { targetInfo: { browserContextId: string } }).targetInfo
      .browserContextId).toBe("ctx-a");
  });

  it("is never told about another client's page", async () => {
    // The property the whole design rests on. If a synthesised discovery event
    // named someone else's target, the client could attach to it — and that
    // target is outside its gate.
    const { proxy, a, b } = proxyWithTwoClients();
    for (const c of ["client-a", "client-b"]) {
      await proxy.handleCommand(c, {
        id: 1,
        method: "Target.setDiscoverTargets",
        params: { discover: true },
      });
    }
    await proxy.handleCommand("client-b", {
      id: 2,
      method: "Target.createTarget",
      params: { url: "https://b-only.example" },
    });

    expect(b.filter((e) => e.method === "Target.targetCreated")).toHaveLength(1);
    expect(
      a.filter((e) => e.method === "Target.targetCreated"),
      "client A learned about a page it does not own",
    ).toHaveLength(0);
    expect(JSON.stringify(a)).not.toContain("b-only.example");
  });

  it("says nothing to a client that never asked for discovery", async () => {
    const { proxy, a } = proxyWithTwoClients();
    await proxy.handleCommand("client-a", {
      id: 1,
      method: "Target.createTarget",
      params: { url: "https://example.com" },
    });
    expect(a.filter((e) => e.method === "Target.targetCreated")).toHaveLength(0);
  });

  it("hears about its page closing", async () => {
    const { proxy, a } = proxyWithTwoClients();
    await proxy.handleCommand("client-a", {
      id: 1,
      method: "Target.setDiscoverTargets",
      params: { discover: true },
    });
    const created = await proxy.handleCommand("client-a", {
      id: 2,
      method: "Target.createTarget",
      params: { url: "https://example.com" },
    });
    const targetId = (created.message.result as { targetId: string }).targetId;
    await proxy.handleCommand("client-a", {
      id: 3,
      method: "Target.closeTarget",
      params: { targetId },
    });
    expect(a.filter((e) => e.method === "Target.targetDestroyed")).toHaveLength(1);
  });

  it("cannot close, or be told about, a target it does not own", async () => {
    const { proxy, a, b } = proxyWithTwoClients();
    await proxy.handleCommand("client-a", {
      id: 1,
      method: "Target.setDiscoverTargets",
      params: { discover: true },
    });
    const created = await proxy.handleCommand("client-b", {
      id: 2,
      method: "Target.createTarget",
      params: { url: "https://b-only.example" },
    });
    const bTarget = (created.message.result as { targetId: string }).targetId;

    await proxy.handleCommand("client-a", {
      id: 3,
      method: "Target.closeTarget",
      params: { targetId: bTarget },
    });
    // A closes nothing of B's, and is told nothing about it either way.
    expect(a.filter((e) => e.method === "Target.targetDestroyed")).toHaveLength(0);
    void b;
  });
});
