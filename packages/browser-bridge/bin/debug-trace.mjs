// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Build an `onStep` handler for `--debug`/`ONECLAW_BRIDGE_DEBUG` that writes
 * `TraceEvent`s to disk: one JSON line per step in `trace.jsonl`, and a
 * numbered PNG file for every step that carries a screenshot (referenced from
 * the JSON by filename — inlining base64 PNG bytes into a JSON line would
 * make the log file unreadable and enormous).
 *
 * Runs one directory per bridge process, named by start time, so repeated
 * runs against the same `--debug` root never collide or overwrite each other.
 *
 * Never throws. This sits on the hot path of every fill, registration and
 * capture — a full disk or a permission error while writing debug output must
 * not fail the operation it is only observing.
 */
export function makeDebugStep(baseDir) {
  const dir = join(baseDir, new Date().toISOString().replace(/[:.]/g, "-"));
  mkdirSync(dir, { recursive: true });
  const tracePath = join(dir, "trace.jsonl");
  let seq = 0;

  console.error(`debug trace: ${dir}`);

  return (event) => {
    try {
      seq += 1;
      const { screenshotPng, ...rest } = event;
      let screenshot;
      if (screenshotPng) {
        screenshot = `${String(seq).padStart(4, "0")}-${event.op}-${event.step}.png`;
        writeFileSync(join(dir, screenshot), screenshotPng);
      }
      appendFileSync(tracePath, `${JSON.stringify({ ...rest, ...(screenshot ? { screenshot } : {}) })}\n`);
    } catch {
      // Best-effort. A broken debug sink must not break the fill it is tracing.
    }
  };
}
