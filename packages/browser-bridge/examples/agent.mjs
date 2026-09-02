// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

/**
 * A minimal CDP client, standing in for an agent's framework.
 *
 * This is the integration surface the bridge actually supports: a client that
 * connects to the URL `startBridge` prints and speaks CDP through the gate. It
 * uses only allowlisted methods — create a target, attach to it, evaluate,
 * navigate, reload — which is the whole point of the gate.
 *
 * The popular Node frameworks (Puppeteer, Playwright, and the Playwright-based
 * agents such as browser-use and Stagehand) do NOT connect through the gate as
 * of v0.1: on attach they call `Browser.getVersion`, which is not allowlisted,
 * and they rely on `Target.setAutoAttach` / `Target.setDiscoverTargets`, which
 * the gate refuses by design — re-attaching outside the gate would defeat it.
 * See examples/README.md. Until that is addressed, a framework integrates by
 * speaking gated CDP directly, the way this class does.
 */
import { WebSocket } from "ws";

export class Agent {
  #ws;
  #next = 1;
  #pending = new Map();

  constructor(ws) {
    this.#ws = ws;
    this.#ws.on("message", (data) => {
      const msg = JSON.parse(String(data));
      if (typeof msg.id === "number") {
        this.#pending.get(msg.id)?.(msg);
        this.#pending.delete(msg.id);
      }
    });
  }

  static async connect(url) {
    const ws = new WebSocket(url);
    await new Promise((res, rej) => {
      ws.once("open", res);
      ws.once("error", rej);
    });
    return new Agent(ws);
  }

  /** Send one CDP command and resolve with the reply. */
  send(msg) {
    const id = this.#next++;
    return new Promise((res) => {
      this.#pending.set(id, res);
      this.#ws.send(JSON.stringify({ id, ...msg }));
    });
  }

  /** Open a tab at `url` and return its target and session ids. */
  async openTab(url) {
    const made = await this.send({ method: "Target.createTarget", params: { url } });
    const targetId = made.result?.targetId;
    if (!targetId) throw new Error("Target.createTarget returned no targetId");
    const attached = await this.send({
      method: "Target.attachToTarget",
      params: { targetId, flatten: true },
    });
    const sessionId = attached.result?.sessionId;
    if (!sessionId) throw new Error("Target.attachToTarget returned no sessionId");
    return { targetId, sessionId };
  }

  /** Evaluate an expression in a tab and return its value. */
  async evaluate(sessionId, expression, awaitPromise = false) {
    const out = await this.send({
      sessionId,
      method: "Runtime.evaluate",
      params: { expression, returnByValue: true, awaitPromise },
    });
    return out.result?.result?.value;
  }

  reload(sessionId) {
    return this.send({ sessionId, method: "Page.reload" });
  }

  close() {
    this.#ws.close();
  }
}
