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
// In-memory, no account required — so this package can be run by someone who
// has not signed up for anything. Not for production; see its module doc.
export {
  MockVaultDriver,
  type MockVaultDriverOptions,
  type MockBinding,
} from "./drivers/mock.js";
// The community backend: your credentials, your machine, no account and no
// server. An AES-256-GCM file keyed by scrypt from a passphrase you hold.
export { LocalVaultDriver, type LocalVaultDriverOptions } from "./drivers/local.js";
export {
  sealVault,
  openVault,
  VAULT_FORMAT,
  type VaultFile,
  type VaultEntry,
  // Exported so one CLI can manage this file. `1claw browser vault` is the
  // only tool for it now, and it must use this implementation rather than a
  // second copy of the format — which is how the product ended up with two
  // encrypted local files whose key derivations did not match.
  type VaultContents,
  type RegistrationPolicy,
  type CapturePolicy,
} from "./drivers/local-vault-file.js";
export { hostAllowed, hostOf } from "./host-match.js";
export * from "@1claw/browser-bridge-protocol";
