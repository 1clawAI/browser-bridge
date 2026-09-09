// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import type { CaptureGrant, Grant, RegistrationGrant } from "@1claw/browser-bridge-protocol";
import { CdpGate } from "./cdp-policy.js";
import { CaptureEngine } from "./capture-engine.js";
import { FakeCdpTransport, type CdpMessage } from "./cdp-transport.js";
import { FillEngine } from "./fill-engine.js";
import { RegistrationEngine } from "./registration-engine.js";
import { SecretHandle } from "./secret-handle.js";
import type { TraceEvent } from "./trace.js";
import type { VaultBackend } from "./vault-backend.js";

/**
 * `onStep` is the one channel in this package explicitly designed to leave the
 * process — to a debug log, a file on disk, eventually a dashboard. Every other
 * secret-handling test in this suite checks that a value does not come back
 * through a *return value*; these check the newer, wider door instead. A
 * screenshot is real pixels from a real page, so the bar here is the same one
 * `trace.ts`'s own doc comment sets: a password never appears in the clear, an
 * `extraFields`/generated value never appears in `detail`, and a capture's
 * secret never appears anywhere at all once generation or reading has begun.
 */

const PASSWORD = "hunter2-trace-secret-9f3a"; // gitleaks:allow -- test fixture, not a credential
const DOB = "1990-01-01-do-not-log-me";
const GENERATED = "generated-api-key-should-never-leak";

/** Not a real PNG, just distinctive bytes a leaked-secret assertion can scan. */
const FAKE_PNG_B64 = Buffer.from("fake-screenshot-bytes").toString("base64");

/** Answers Page.captureScreenshot with fake bytes; everything else passes through. */
function withScreenshots(transport: FakeCdpTransport): FakeCdpTransport {
  const original = transport.send.bind(transport);
  vi.spyOn(transport, "send").mockImplementation(async (msg: CdpMessage) => {
    if (msg.method === "Page.captureScreenshot") {
      return { ...(msg.id !== undefined ? { id: msg.id } : {}), result: { data: FAKE_PNG_B64 } };
    }
    return original(msg);
  });
  return transport;
}

function noSecretLeaked(events: readonly TraceEvent[], ...secrets: string[]): void {
  for (const e of events) {
    for (const secret of secrets) {
      expect(e.detail ?? "", `step "${e.step}" leaked a secret into detail`).not.toContain(secret);
      if (e.screenshotPng) {
        const asText = Buffer.from(e.screenshotPng).toString("latin1");
        expect(asText, `step "${e.step}" leaked a secret into a screenshot`).not.toContain(secret);
      }
    }
  }
}

describe("fill trace", () => {
  const GRANT: Grant = {
    kind: "grant",
    grantId: "g1",
    bindingId: "b1",
    loginUrl: "https://app.example.com/login",
    expiresAt: "",
    generation: 7,
    username: "ada@example.com",
    usernameSelector: "#user",
  };

  function deps() {
    const events: TraceEvent[] = [];
    const gate = new CdpGate();
    const transport = withScreenshots(new FakeCdpTransport());
    const backend = { consumeFill: async () => SecretHandle.fromUtf8(PASSWORD) } as unknown as VaultBackend;
    const engine = new FillEngine({
      backend,
      transport,
      gate,
      currentGeneration: () => GRANT.generation,
      onStep: (e) => events.push(e),
    });
    return { engine, events };
  }

  it("emits one step per stage of a successful fill, in order", async () => {
    const { engine, events } = deps();
    const out = await engine.fill("agent-target", GRANT, "#password");
    expect(out).toEqual({ status: "filled" });
    expect(events.map((e) => e.step)).toEqual([
      "navigate",
      "type_username",
      "wait_for_field",
      "focus",
      "type_secret",
      "submit",
      "settle",
      "closed",
    ]);
    expect(events.every((e) => e.op === "fill" && e.id === "b1")).toBe(true);
  });

  it("never puts the password in a detail string or a screenshot", async () => {
    const { engine, events } = deps();
    await engine.fill("agent-target", GRANT, "#password");
    noSecretLeaked(events, PASSWORD);
  });

  it("screenshots navigate and settle, but never the type_secret step", async () => {
    const { engine, events } = deps();
    await engine.fill("agent-target", GRANT, "#password");
    const byStep = new Map(events.map((e) => [e.step, e]));
    expect(byStep.get("navigate")?.screenshotPng).toBeDefined();
    expect(byStep.get("settle")?.screenshotPng).toBeDefined();
    // The one step this file exists to protect: the password is on the page
    // at exactly this moment, so this step is traced but never pictured.
    expect(byStep.get("type_secret")?.screenshotPng).toBeUndefined();
  });

  it("still leaks nothing when the transport fails after typing the secret", async () => {
    const events: TraceEvent[] = [];
    const gate = new CdpGate();
    const transport = new FakeCdpTransport();
    vi.spyOn(transport, "send").mockImplementation(async (msg: CdpMessage) => {
      if (msg.method === "Input.dispatchKeyEvent") throw new Error("browser died mid-submit");
      return FakeCdpTransport.prototype.send.call(transport, msg);
    });
    const backend = { consumeFill: async () => SecretHandle.fromUtf8(PASSWORD) } as unknown as VaultBackend;
    const engine = new FillEngine({
      backend,
      transport,
      gate,
      currentGeneration: () => GRANT.generation,
      onStep: (e) => events.push(e),
    });
    const out = await engine.fill("agent-target", GRANT, "#password");
    expect(out.status).toBe("error");
    expect(events.map((e) => e.step)).toContain("error");
    noSecretLeaked(events, PASSWORD);
  });

  it("a broken onStep handler does not abort an otherwise-successful fill", async () => {
    const gate = new CdpGate();
    const transport = new FakeCdpTransport();
    const backend = { consumeFill: async () => SecretHandle.fromUtf8(PASSWORD) } as unknown as VaultBackend;
    const engine = new FillEngine({
      backend,
      transport,
      gate,
      currentGeneration: () => GRANT.generation,
      onStep: () => {
        throw new Error("the operator's own handler is broken");
      },
    });
    const out = await engine.fill("agent-target", GRANT, "#password");
    expect(out).toEqual({ status: "filled" });
  });
});

describe("registration trace", () => {
  const GRANT: RegistrationGrant = {
    kind: "registration_grant",
    registrationId: "r1",
    signupUrl: "https://acme.example.com/signup",
    username: "ada@example.com",
    usernameSelector: "#email",
    passwordSelector: "#password",
    extraFields: [{ selector: "#dob", value: DOB }],
    // FakeCdpTransport answers every selector-presence probe with `true` by
    // default, so a `selector` success signal resolves on the first poll.
    // `urlChanges` would not: this engine's own submit path calls
    // `form.submit()` via eval rather than dispatching a key event, and the
    // fake only advances its simulated URL off the back of a dispatched key —
    // so `urlChanges` here would poll for the full settle timeout every run.
    success: { selector: "#registered-ok" },
  };

  function deps() {
    const events: TraceEvent[] = [];
    const gate = new CdpGate();
    const transport = withScreenshots(new FakeCdpTransport());
    const engine = new RegistrationEngine({
      transport,
      gate,
      takeSecret: async () => SecretHandle.fromUtf8(PASSWORD),
      commit: async () => ({ bindingId: "b1" }),
      cancel: async () => {},
      onStep: (e) => events.push(e),
    });
    return { engine, events };
  }

  it("traces every field, including extraFields, without the password or its own detail leaking", async () => {
    const { engine, events } = deps();
    const out = await engine.register(GRANT);
    expect(out).toEqual({ status: "registered", bindingId: "b1" });
    expect(events.map((e) => e.step)).toEqual([
      "navigate",
      "type_username",
      "type_extra_field",
      "type_secret",
      "submit",
      "settle",
      "closed",
    ]);
    noSecretLeaked(events, PASSWORD);
    // extraFields carries a real value (DOB), typed as plain text; the rule
    // from trace.ts is that `detail` is a selector or reason only, never the
    // value itself — so DOB may legally appear in a screenshot (the page
    // renders it) but never in a `detail` string.
    for (const e of events) {
      expect(e.detail ?? "").not.toContain(DOB);
    }
    const extraField = events.find((e) => e.step === "type_extra_field");
    expect(extraField?.detail).toBe("#dob");
  });

  it("screenshots navigate and settle, never type_secret", async () => {
    const { engine, events } = deps();
    await engine.register(GRANT);
    const byStep = new Map(events.map((e) => [e.step, e]));
    expect(byStep.get("navigate")?.screenshotPng).toBeDefined();
    expect(byStep.get("settle")?.screenshotPng).toBeDefined();
    expect(byStep.get("type_secret")?.screenshotPng).toBeUndefined();
  });
});

describe("capture trace", () => {
  const GRANT: CaptureGrant = {
    kind: "capture_grant",
    captureId: "c1",
    captureUrl: "https://acme.example.com/settings/api-key",
    source: { valueSelector: "#api-key", valueProp: "value" },
    entryId: "e1",
  };

  function deps() {
    const events: TraceEvent[] = [];
    const gate = new CdpGate();
    const transport = withScreenshots(new FakeCdpTransport());
    // Runtime.evaluate answers every non-location.href expression with this
    // value, which is exactly what #readValue reads as "the generated secret".
    transport.evaluateValue = GENERATED;
    const engine = new CaptureEngine({
      transport,
      gate,
      commit: async () => ({ entryId: "e1" }),
      cancel: async () => {},
      onStep: (e) => events.push(e),
    });
    return { engine, events };
  }

  it("traces navigate and read_value, but the generated secret never appears anywhere", async () => {
    const { engine, events } = deps();
    const out = await engine.capture("agent-target", GRANT);
    expect(out).toEqual({ status: "captured", entryId: "e1" });
    expect(events.map((e) => e.step)).toEqual(["navigate", "read_value", "committed", "closed"]);
    noSecretLeaked(events, GENERATED);
    // read_value's detail is the selector it read from, never what it found.
    const readValue = events.find((e) => e.step === "read_value");
    expect(readValue?.ok).toBe(true);
    expect(readValue?.detail).toBe("#api-key");
  });

  it("the only screenshot in a capture is the one before the value exists", async () => {
    const { engine, events } = deps();
    await engine.capture("agent-target", GRANT);
    const byStep = new Map(events.map((e) => [e.step, e]));
    expect(byStep.get("navigate")?.screenshotPng).toBeDefined();
    // Everything from here on could be showing the secret; none of it pictures it.
    for (const step of ["read_value", "committed", "closed"]) {
      expect(byStep.get(step)?.screenshotPng, `"${step}" must never carry a screenshot`).toBeUndefined();
    }
  });
});
