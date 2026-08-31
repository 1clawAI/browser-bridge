// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { PROTOCOL_VERSION, type DenyReason } from "./index.js";

describe("protocol", () => {
  it("publishes a semver the vault can gate on", () => {
    expect(PROTOCOL_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  // Free text in a refusal reaches agent-visible output, and an agent that can
  // read a reason will try to argue with it. The set is closed on purpose.
  it("keeps deny reasons a closed set that names no credential", () => {
    const reasons: DenyReason[] = [
      "origin_not_allowed", "frame_origin_mismatch", "form_action_not_allowed",
      "redirect_chain_not_allowed", "form_fingerprint_drift", "generation_stale",
      "velocity_exceeded", "capability_unavailable", "policy_denied",
      "session_expired", "fill_in_progress",
    ];
    for (const r of reasons) {
      expect(r).toMatch(/^[a-z_]+$/);
    }
  });
});
