// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

export { SecretHandle } from "./secret-handle.js";
export { CdpGate, type CdpCommand, type CdpDecision, type CdpDenyReason, type CdpEvent } from "./cdp-policy.js";
export { checkLoopbackRequest, type LoopbackCheck, type LoopbackRequest } from "./loopback.js";
export { CdpProxy, type ClientId, type ProxyReply } from "./cdp-proxy.js";
export { FakeCdpTransport, type CdpMessage, type CdpTransport } from "./cdp-transport.js";
export { PipeCdpTransport, type PipeTransportOptions } from "./pipe-transport.js";
export { PipeDecoder, encodeMessage } from "./pipe-codec.js";
export { CAPABILITY_TOOLS, toolsFor, type VaultBackend } from "./vault-backend.js";
export { SaasDriver, type SaasDriverOptions } from "./drivers/saas.js";
export * from "@1claw/browser-bridge-protocol";
