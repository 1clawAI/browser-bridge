// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { createServer, type IncomingMessage, type Server } from "node:http";
import { randomUUID } from "node:crypto";
import type { Duplex } from "node:stream";
import { WebSocketServer, type WebSocket } from "ws";
import { CdpProxy } from "./cdp-proxy.js";
import type { CdpMessage, CdpTransport } from "./cdp-transport.js";
import { checkLoopbackRequest } from "./loopback.js";

/**
 * The socket a framework points `cdp_url` at.
 *
 * Everything an agent can do to Chromium arrives here, so the checks happen at
 * the *upgrade*, before a socket exists at all. Authenticating after the
 * handshake would mean an unauthorised page already holds an open connection to
 * the thing being protected, and closing it afterwards is a race rather than a
 * boundary.
 *
 * Bound to 127.0.0.1 by default, which is necessary and nowhere near
 * sufficient: the browser this bridge drives can reach loopback too. See
 * `checkLoopbackRequest` for what actually separates a bridge client from a
 * page — briefly, any `Origin` at all, a non-literal `Host`, or a wrong token.
 */
export type ProxyServerOptions = {
  readonly transport: CdpTransport;
  /** Per-session token, minted at bridge start and carried in the URL path. */
  readonly token: string;
  readonly host?: string;
  readonly port?: number;
  /** Allocates a BrowserContext for a newly connected client. */
  readonly createContext?: (clientId: string) => Promise<string> | string;
};

export class CdpProxyServer {
  readonly #http: Server;
  readonly #wss: WebSocketServer;
  readonly #proxy: CdpProxy;
  readonly #opts: ProxyServerOptions;

  constructor(opts: ProxyServerOptions) {
    this.#opts = opts;
    this.#proxy = new CdpProxy(opts.transport);
    // noServer: the upgrade is handled by hand so the loopback checks run
    // before any socket is created.
    this.#wss = new WebSocketServer({ noServer: true });
    this.#http = createServer((_req, res) => {
      // Plain HTTP has no business here; the only surface is the upgrade.
      res.writeHead(404).end();
    });
    this.#http.on("upgrade", (req, socket, head) => this.#onUpgrade(req, socket, head));
  }

  get proxy(): CdpProxy {
    return this.#proxy;
  }

  async listen(): Promise<{ host: string; port: number; url: string }> {
    const host = this.#opts.host ?? "127.0.0.1";
    const port = this.#opts.port ?? 0;
    await new Promise<void>((resolve) => this.#http.listen(port, host, resolve));
    const addr = this.#http.address();
    if (!addr || typeof addr === "string") throw new Error("server did not bind a port");
    return {
      host,
      port: addr.port,
      url: `ws://${host}:${addr.port}/cdp/${this.#opts.token}`,
    };
  }

  async close(): Promise<void> {
    for (const client of this.#wss.clients) client.close();
    this.#wss.close();
    await new Promise<void>((resolve) => this.#http.close(() => resolve()));
    await this.#proxy.close();
  }

  #onUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    const check = checkLoopbackRequest(
      { headers: req.headers as Record<string, string | undefined>, path: req.url ?? "/" },
      this.#opts.token,
    );

    if (!check.ok) {
      // A refusal at the HTTP layer, not a WebSocket close: the connection is
      // never established, so there is no moment where a page holds a socket.
      const status = check.status === 404 ? "404 Not Found" : "403 Forbidden";
      socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
      socket.destroy();
      return;
    }

    this.#wss.handleUpgrade(req, socket, head, (ws) => void this.#onClient(ws));
  }

  async #onClient(ws: WebSocket): Promise<void> {
    const clientId = randomUUID();
    // Its own context by default: sharing one means a second agent inherits the
    // first's cookies and is silently logged in as it.
    const contextId = (await this.#opts.createContext?.(clientId)) ?? `ctx-${clientId}`;

    this.#proxy.register(clientId, contextId, (evt) => {
      if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(evt));
    });

    ws.on("message", (raw) => void this.#onMessage(ws, clientId, raw));
    ws.on("close", () => this.#proxy.unregister(clientId));
    ws.on("error", () => this.#proxy.unregister(clientId));
  }

  async #onMessage(ws: WebSocket, clientId: string, raw: unknown): Promise<void> {
    let msg: CdpMessage;
    try {
      msg = JSON.parse(String(raw)) as CdpMessage;
    } catch {
      // Malformed input is answered, not ignored: silence looks like a hang to
      // a framework waiting on a reply.
      ws.send(JSON.stringify({ error: { code: -32700, message: "invalid JSON" } }));
      return;
    }

    try {
      const reply = await this.#proxy.handleCommand(clientId, msg);
      if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(reply.message));
    } catch (e) {
      if (ws.readyState === ws.OPEN) {
        ws.send(
          JSON.stringify({
            ...(msg.id !== undefined ? { id: msg.id } : {}),
            error: { code: -32000, message: e instanceof Error ? e.message : String(e) },
          }),
        );
      }
    }
  }
}
