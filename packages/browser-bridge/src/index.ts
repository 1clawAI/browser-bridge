// Copyright (C) 2026 1Claw
// SPDX-License-Identifier: Apache-2.0

// The composition root. Everything below is a part; this is the assembled
// system, and the only thing a caller should need to start a bridge.
export { startBridge, type BridgeOptions, type BridgeHandle } from "./bridge.js";

export { SecretHandle } from "./secret-handle.js";
export { CdpGate, type CdpCommand, type CdpDecision, type CdpDenyReason, type CdpEvent } from "./cdp-policy.js";
export { checkLoopbackRequest, type LoopbackCheck, type LoopbackRequest } from "./loopback.js";
export { CdpProxy, type ClientId, type ProxyReply } from "./cdp-proxy.js";
export { FakeCdpTransport, type CdpMessage, type CdpTransport } from "./cdp-transport.js";
export { PipeCdpTransport, type PipeTransportOptions } from "./pipe-transport.js";
export { PipeDecoder, encodeMessage } from "./pipe-codec.js";
export { CdpProxyServer, type ProxyServerOptions } from "./proxy-server.js";
export { buildToolset, dispatchTool, type ToolDefinition, type ToolResult } from "./mcp-tools.js";
export { FillEngine, type FillEngineDeps, type FillOutcome } from "./fill-engine.js";
export { CAPABILITY_TOOLS, toolsFor, type VaultBackend } from "./vault-backend.js";
export { SaasDriver, type SaasDriverOptions } from "./drivers/saas.js";
export * from "@1claw/browser-bridge-protocol";
