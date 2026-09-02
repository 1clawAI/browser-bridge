// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { CdpProxy } from "./cdp-proxy.js";
import { FakeCdpTransport } from "./cdp-transport.js";

/**
 * Commands, not events.
 *
 * Event delivery was confined per client and commands were not, which is a gap
 * that reads as closed: the class has a full events-confinement test block and
 * nothing on the command side. `Target.getTargets`, `getTargetInfo` and
 * `attachToTarget` are all allowlisted, and none of them checked that the
 * target named belongs to the caller's browser context.
 *
 * So client B could list A's targets, attach to one, and drive it with the
 * sessionId Chromium returned — `Runtime.evaluate` on A's page, or
 * `Network.getCookies` for A's session. That is the outcome this class exists
 * to prevent, stated in its own doc comment: agent B is simply logged in as A.
 *
 * `#sessionOwners` was already being recorded on every attach. It was read in
 * the event path and nowhere else, so the information needed to refuse was
 * present and unused.
 */
function twoClients() {
  const transport = new FakeCdpTransport();
  const proxy = new CdpProxy(transport);
  proxy.register("client-a", "ctx-a", () => {});
  proxy.register("client-b", "ctx-b", () => {});
  return { proxy, transport };
}

/** A page belonging to A, created the way a client creates one. */
async function aPageOwnedByA(proxy: CdpProxy): Promise<string> {
  const created = await proxy.handleCommand("client-a", {
    id: 1,
    method: "Target.createTarget",
    params: { url: "https://bank.example/account" },
  });
  return (created.message.result as { targetId: string }).targetId;
}

describe("a client reaching for another client's target", () => {
  it("cannot attach to it", async () => {
    const { proxy } = twoClients();
    const aTarget = await aPageOwnedByA(proxy);

    const reply = await proxy.handleCommand("client-b", {
      id: 2,
      method: "Target.attachToTarget",
      params: { targetId: aTarget, flatten: true },
    });

    expect(reply.kind, "B attached to A's page").toBe("refuse");
    expect(reply.message.error).toBeTruthy();
  });

  it("cannot ask about it", async () => {
    const { proxy } = twoClients();
    const aTarget = await aPageOwnedByA(proxy);

    const reply = await proxy.handleCommand("client-b", {
      id: 2,
      method: "Target.getTargetInfo",
      params: { targetId: aTarget },
    });
    expect(reply.kind).toBe("refuse");
  });

  it("does not see it listed", async () => {
    const { proxy } = twoClients();
    const aTarget = await aPageOwnedByA(proxy);
    await proxy.handleCommand("client-b", {
      id: 2,
      method: "Target.createTarget",
      params: { url: "https://b-own.example" },
    });

    const reply = await proxy.handleCommand("client-b", { id: 3, method: "Target.getTargets" });
    const listed = (reply.message.result as { targetInfos?: { targetId: string }[] })?.targetInfos;
    expect(listed, "getTargets returned an unfiltered list").toBeDefined();
    expect(listed!.map((t) => t.targetId)).not.toContain(aTarget);
    expect(JSON.stringify(reply.message)).not.toContain("bank.example");
  });

  it("cannot drive it with a session it did not open", async () => {
    // The end of the chain: even handed a valid sessionId, a command carrying
    // it must be refused unless the session belongs to the caller.
    const { proxy } = twoClients();
    const aTarget = await aPageOwnedByA(proxy);
    const attached = await proxy.handleCommand("client-a", {
      id: 2,
      method: "Target.attachToTarget",
      params: { targetId: aTarget, flatten: true },
    });
    const aSession = (attached.message.result as { sessionId: string }).sessionId;
    expect(aSession, "A's own attach should succeed").toBeTruthy();

    for (const method of ["Runtime.evaluate", "Network.getCookies", "Page.navigate"]) {
      const reply = await proxy.handleCommand("client-b", {
        id: 9,
        method,
        sessionId: aSession,
        params: { expression: "document.body.innerText" },
      });
      expect(reply.kind, `B drove A's page with ${method}`).toBe("refuse");
    }
  });

  it("still works normally on its own target", async () => {
    // The confinement must not cost a client the use of its own page.
    const { proxy } = twoClients();
    const created = await proxy.handleCommand("client-b", {
      id: 1,
      method: "Target.createTarget",
      params: { url: "https://b-own.example" },
    });
    const bTarget = (created.message.result as { targetId: string }).targetId;

    const attached = await proxy.handleCommand("client-b", {
      id: 2,
      method: "Target.attachToTarget",
      params: { targetId: bTarget, flatten: true },
    });
    expect(attached.kind).toBe("forward");
    const bSession = (attached.message.result as { sessionId: string }).sessionId;

    const info = await proxy.handleCommand("client-b", {
      id: 3,
      method: "Target.getTargetInfo",
      params: { targetId: bTarget },
    });
    expect(info.kind).toBe("forward");

    const evaluated = await proxy.handleCommand("client-b", {
      id: 4,
      method: "Runtime.evaluate",
      sessionId: bSession,
      params: { expression: "1+1" },
    });
    expect(evaluated.kind).toBe("forward");
  });
});
