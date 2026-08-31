// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from "vitest";
import WebSocket from "ws";
import { CdpProxyServer } from "./proxy-server.js";
import { FakeCdpTransport } from "./cdp-transport.js";

const TOKEN = "tok-abcdefghijklmnopqrstuvwx";

let open: CdpProxyServer[] = [];
afterEach(async () => {
  for (const s of open) await s.close().catch(() => {});
  open = [];
});

async function start() {
  const transport = new FakeCdpTransport();
  const server = new CdpProxyServer({ transport, token: TOKEN });
  open.push(server);
  const { url, port } = await server.listen();
  return { transport, server, url, port };
}

/** Connect and resolve with the handshake outcome rather than throwing. */
function connect(url: string, headers: Record<string, string> = {}) {
  return new Promise<{ ok: boolean; status?: number; ws?: WebSocket }>((resolve) => {
    const ws = new WebSocket(url, { headers });
    ws.on("open", () => resolve({ ok: true, ws }));
    ws.on("unexpected-response", (_req, res) => resolve({ ok: false, status: res.statusCode }));
    ws.on("error", () => resolve({ ok: false }));
  });
}

const send = (ws: WebSocket, msg: unknown) =>
  new Promise<Record<string, unknown>>((resolve) => {
    ws.once("message", (raw) => resolve(JSON.parse(String(raw))));
    ws.send(JSON.stringify(msg));
  });

describe("upgrade is where the checks happen", () => {
  it("accepts a client with the right token and no Origin", async () => {
    const { url } = await start();
    const r = await connect(url);
    expect(r.ok).toBe(true);
    r.ws?.close();
  });

  /**
   * The case the whole loopback check exists for: a page inside the browser
   * being driven can reach 127.0.0.1, and localhost-to-localhost is same-site,
   * so a Sec-Fetch-Site check would wave it through.
   */
  it("refuses a browser page, which always sends Origin", async () => {
    const { url } = await start();
    for (const origin of ["http://127.0.0.1:3000", "https://evil.example"]) {
      const r = await connect(url, { Origin: origin });
      expect(r.ok, origin).toBe(false);
      expect(r.status, origin).toBe(403);
    }
  });

  it("refuses a wrong token with 404 rather than confirming the endpoint", async () => {
    const { port } = await start();
    const r = await connect(`ws://127.0.0.1:${port}/cdp/wrong-token`);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(404);
  });

  it("refuses a non-loopback Host, the tell for DNS rebinding", async () => {
    const { port } = await start();
    const r = await connect(`ws://127.0.0.1:${port}/cdp/${TOKEN}`, { Host: "evil.example" });
    expect(r.ok).toBe(false);
    expect(r.status).toBe(403);
  });

  // Refused at the HTTP layer, so no socket is ever established — closing one
  // after the fact would be a race, not a boundary.
  it("never establishes a socket for a refused upgrade", async () => {
    const { server, port } = await start();
    await connect(`ws://127.0.0.1:${port}/cdp/nope`);
    expect(server.proxy.contextOf("any")).toBeUndefined();
  });

  it("answers plain HTTP with 404 — the only surface is the upgrade", async () => {
    const { port } = await start();
    const res = await fetch(`http://127.0.0.1:${port}/cdp/${TOKEN}`);
    expect(res.status).toBe(404);
  });
});

describe("command flow over the socket", () => {
  it("forwards an allowed command and returns the reply", async () => {
    const { url, transport } = await start();
    const { ws } = await connect(url);
    const reply = await send(ws!, { id: 1, method: "DOM.getDocument" });
    expect(reply.result).toBeDefined();
    expect(transport.sent).toHaveLength(1);
    ws!.close();
  });

  it("refuses a blocked command without it reaching the browser", async () => {
    const { url, transport } = await start();
    const { ws } = await connect(url);
    const reply = await send(ws!, { id: 2, method: "Network.getRequestPostData" });
    expect((reply.error as { message: string }).message).toMatch(/body_access_denied/);
    expect(transport.sent, "a refused command must never reach Chromium").toHaveLength(0);
    ws!.close();
  });

  it("blocks the whole target during a fill and says why", async () => {
    const { url, server, transport } = await start();
    const { ws } = await connect(url);
    server.proxy.gate.openFillWindow("t1");
    const reply = await send(ws!, {
      id: 3,
      method: "Runtime.evaluate",
      params: { targetId: "t1", expression: "document.querySelector('input').value" },
    });
    expect((reply.error as { message: string }).message).toMatch(/fill_in_progress/);
    expect(transport.sent).toHaveLength(0);
    ws!.close();
  });

  it("answers malformed JSON instead of leaving the caller waiting", async () => {
    const { url } = await start();
    const { ws } = await connect(url);
    const reply = await new Promise<Record<string, unknown>>((resolve) => {
      ws!.once("message", (raw) => resolve(JSON.parse(String(raw))));
      ws!.send("{not json");
    });
    expect((reply.error as { code: number }).code).toBe(-32700);
    ws!.close();
  });
});

describe("clients are isolated and cleaned up", () => {
  it("gives each connection its own context", async () => {
    const seen: string[] = [];
    const transport = new FakeCdpTransport();
    const server = new CdpProxyServer({
      transport,
      token: TOKEN,
      createContext: (id) => {
        const ctx = `ctx-${seen.length}`;
        seen.push(id);
        return ctx;
      },
    });
    open.push(server);
    const { url } = await server.listen();

    const a = await connect(url);
    const b = await connect(url);
    expect(seen).toHaveLength(2);
    expect(seen[0]).not.toBe(seen[1]);
    a.ws?.close();
    b.ws?.close();
  });

  it("delivers events to connected clients", async () => {
    const { url, transport } = await start();
    const { ws } = await connect(url);
    const evt = new Promise<Record<string, unknown>>((resolve) => {
      ws!.once("message", (raw) => resolve(JSON.parse(String(raw))));
    });
    transport.emit({ method: "Page.loadEventFired", params: { targetId: "t1" } });
    expect((await evt).method).toBe("Page.loadEventFired");
    ws!.close();
  });

  it("unregisters a client when its socket closes", async () => {
    const { url, server } = await start();
    const { ws } = await connect(url);
    await new Promise((r) => {
      ws!.on("close", r);
      ws!.close();
    });
    await new Promise((r) => setTimeout(r, 50));
    // No client remains to receive anything.
    expect(server.proxy.contextOf("any")).toBeUndefined();
  });
});
