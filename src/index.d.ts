/// <reference types="node" />

import type { Duplex } from 'node:stream'
import type { EventEmitter } from 'node:events'

export interface PqIdentity {
  publicKey: Uint8Array | Buffer
  secretKey: Uint8Array | Buffer
}

export interface ChannelOptions {
  role:      'initiator' | 'responder'
  /** ML-DSA-65 keypair for mutual authentication. Optional. */
  identity?: PqIdentity
}

export interface HandshakeOptions {
  identity?: PqIdentity
}

export interface SessionKeys {
  txKey: Uint8Array
  rxKey: Uint8Array
}

/**
 * Wrap a Node.js Duplex stream (e.g. `net.Socket`) with a post-quantum secure
 * channel. Resolves once the handshake completes.
 *
 * Key exchange: ML-KEM-768 + X25519. Session encryption: AES-256-GCM.
 * Optional mutual auth via ML-DSA-65 Finished frames.
 */
export function wrapStream(socket: Duplex, options: ChannelOptions): Promise<Duplex>

/**
 * Wrap a WebSocket (native API or `ws` package) with a post-quantum secure
 * channel. Resolves once the handshake completes.
 */
export function wrapWebSocket(ws: unknown, options: ChannelOptions): Promise<PqTlsWebSocket>

/**
 * Encrypted WebSocket wrapper returned by `wrapWebSocket`.
 * Emits `message`, `close`, and `error` events.
 */
export declare class PqTlsWebSocket extends EventEmitter {
  send(data: string | Buffer | Uint8Array): void
  close(code?: number, reason?: string | Buffer): void
}

// ── Low-level handshake API ───────────────────────────────────────────────────

type SendFn = (data: Buffer) => Promise<void>
type RecvFn = (n: number)   => Promise<Buffer>

/** Run the initiator side of the PQ-TLS handshake over custom send/recv functions. */
export function initiatorHandshake(
  send:     SendFn,
  recv:     RecvFn,
  options?: HandshakeOptions,
): Promise<SessionKeys>

/** Run the responder side of the PQ-TLS handshake over custom send/recv functions. */
export function responderHandshake(
  send:     SendFn,
  recv:     RecvFn,
  options?: HandshakeOptions,
): Promise<SessionKeys>

export class KxcoPqTlsError extends Error {
  name: 'KxcoPqTlsError'
}
