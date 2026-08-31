// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0
//
// A stand-in for Chromium that speaks CDP over the same pipe: reads commands
// from fd 3, writes replies and events to fd 4, NUL-delimited.
//
// This exists so the transport's real spawn/descriptor/framing path is covered
// without a 150MB browser download in CI. Chromium-specific behaviour is a
// separate, opt-in test; everything here is protocol, and protocol is where the
// bugs are.
import fs from "node:fs";

const read = fs.createReadStream(null, { fd: 3 });
const write = fs.createWriteStream(null, { fd: 4 });

const send = (obj) => write.write(Buffer.concat([Buffer.from(JSON.stringify(obj)), Buffer.from([0])]));

let buffer = Buffer.alloc(0);
read.on("data", (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  for (;;) {
    const nul = buffer.indexOf(0);
    if (nul === -1) break;
    const raw = buffer.subarray(0, nul);
    buffer = buffer.subarray(nul + 1);
    if (raw.length === 0) continue;
    const msg = JSON.parse(raw.toString("utf8"));

    if (msg.method === "Test.emitEvent") {
      send({ id: msg.id, result: {} });
      send({ method: "Page.loadEventFired", params: { targetId: "t1" } });
    } else if (msg.method === "Test.neverReply") {
      // Deliberately silent, to exercise the command timeout.
    } else if (msg.method === "Test.crash") {
      process.exit(3);
    } else if (msg.method === "Test.garbage") {
      write.write(Buffer.concat([Buffer.from("{not json"), Buffer.from([0])]));
    } else {
      send({ id: msg.id, result: { echoed: msg.method } });
    }
  }
});
