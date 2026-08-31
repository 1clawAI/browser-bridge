// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PipeCdpTransport } from "./pipe-transport.js";

const FAKE = join(dirname(fileURLToPath(import.meta.url)), "test-fixtures", "fake-browser.mjs");

/**
 * Exercises the real spawn, the real file descriptors and the real framing —
 * against a stand-in that speaks the pipe protocol rather than Chromium. The
 * browser-specific behaviour is a separate opt-in test; everything here is
 * protocol, which is where the bugs live.
 */
function launch(commandTimeoutMs = 2000) {
  // attach(), not launch(): launch() prepends Chromium's own flags, and node
  // rejects --remote-debugging-pipe outright (exit code 9). The stdio layout
  // here is the one launch() uses, so the descriptor wiring under test is real.
  const child = spawn(process.execPath, [FAKE], {
    stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"],
  });
  return PipeCdpTransport.attach(child, commandTimeoutMs);
}

describe("pipe transport", () => {
  it("sends a command down fd 3 and resolves the reply from fd 4", async () => {
    const t = launch();
    const reply = await t.send({ method: "Page.enable" });
    expect(reply.result).toEqual({ echoed: "Page.enable" });
    await t.close();
  });

  it("correlates concurrent commands by id rather than by arrival order", async () => {
    const t = launch();
    const [a, b, c] = await Promise.all([
      t.send({ method: "A" }),
      t.send({ method: "B" }),
      t.send({ method: "C" }),
    ]);
    expect(a.result).toEqual({ echoed: "A" });
    expect(b.result).toEqual({ echoed: "B" });
    expect(c.result).toEqual({ echoed: "C" });
    await t.close();
  });

  it("routes an unsolicited message to event listeners, not to a pending command", async () => {
    const t = launch();
    const events: unknown[] = [];
    t.onEvent((e) => events.push(e));
    await t.send({ method: "Test.emitEvent" });
    await new Promise((r) => setTimeout(r, 100));
    expect(events).toHaveLength(1);
    expect((events[0] as { method: string }).method).toBe("Page.loadEventFired");
    await t.close();
  });

  // A wedged browser should surface as an error, not a caller hanging forever
  // with a pending entry that never clears.
  it("times out a command that is never answered", async () => {
    const t = launch(150);
    await expect(t.send({ method: "Test.neverReply" })).rejects.toThrow(/timed out/);
    await t.close();
  });

  it("rejects in-flight commands when the browser exits", async () => {
    const t = launch(5000);
    const pending = t.send({ method: "Test.neverReply" });
    await t.send({ method: "Test.crash" }).catch(() => {});
    await expect(pending).rejects.toThrow(/exited|closed/);
    await t.close();
  });

  // A framing failure means the stream is no longer trustworthy; continuing
  // would deliver whatever happens to parse next.
  it("fails pending commands when the stream stops being parseable", async () => {
    const t = launch(5000);
    const pending = t.send({ method: "Test.neverReply" });
    await t.send({ method: "Test.garbage" }).catch(() => {});
    await expect(pending).rejects.toThrow();
    await t.close();
  });

  it("refuses to send after close", async () => {
    const t = launch();
    await t.close();
    await expect(t.send({ method: "Page.enable" })).rejects.toThrow(/closed/);
  });

  it("is safe to close twice", async () => {
    const t = launch();
    await t.close();
    await expect(t.close()).resolves.toBeUndefined();
  });
});
