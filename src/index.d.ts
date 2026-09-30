/// <reference types="node" />

import type { Duplex } from 'node:stream'
import type { EventEmitter } from 'node:events'

export interface PqIdentity {
  publicKey: Uint8Array | Buffer
  secretKey: Uint8Array | Buffer
}

export interface ChannelOptions {
  role:      'initiator' | 'responder'
  /**
   * ML-DSA-65 keypair for mutual authentication. Optional. A responder given
   * one refuses an initiator that does not authenticate too.
   */
  identity?: PqIdentity
  /**
   * The ML-DSA-65 public key (1952 bytes) the peer must prove. Optional, and
   * needs an `identity` on this side, because the peer proves its key only in
   * a mutual handshake. A peer that proves any other key fails the handshake
   * with `KxcoPqTlsError`.
   *
   * Mutual authentication proves the peer holds the private half of the key
   * it presented, not that it is the key you expect: a relay holding a key of
   * its own also completes the handshake. Pin the key here, or compare the
   * channel's `peerPublicKey` yourself.
   */
  peerPublicKey?: Uint8Array | Buffer
  /**
   * Total deadline for the handshake, in milliseconds. Defaults to 30000.
   * Set to 0 to wait indefinitely.
   *
   * An initiator configured with an `identity` expects a Finished frame, and a
   * responder with no identity of its own never sends one, so that mismatch
   * stalls rather than failing. This bounds that wait.
   */
  handshakeTimeoutMs?: number
}

export interface HandshakeOptions {
  identity?: PqIdentity
  /** The ML-DSA-65 public key the peer must prove. See `ChannelOptions`. */
  peerPublicKey?: Uint8Array | Buffer
  /**
   * Total deadline for the handshake, in milliseconds. Defaults to 30000.
   * Set to 0 to wait indefinitely.
   */
  handshakeTimeoutMs?: number
}

export interface SessionKeys {
  /**
   * After mutual authentication, each side's Finished frame was sealed under
   * these keys as sequence 0. A record layer of your own starts at 1.
   */
  txKey: Uint8Array
  rxKey: Uint8Array
  /** The ML-DSA-65 public key the peer proved, or `undefined` without mutual authentication. */
  peerPublicKey: Uint8Array | undefined
}

/** The encrypted `Duplex` returned by `wrapStream`. */
export interface PqTlsStream extends Duplex {
  /** The ML-DSA-65 public key the peer proved, or `undefined` without mutual authentication. */
  readonly peerPublicKey: Uint8Array | undefined
}

/**
 * Wrap a Node.js Duplex stream (e.g. `net.Socket`) with a post-quantum secure
 * channel. Resolves once the handshake completes. If the handshake fails, the
 * socket is destroyed before the promise rejects.
 *
 * Key exchange: ML-KEM-768 + X25519. Session encryption: AES-256-GCM.
 * Optional mutual auth via ML-DSA-65 Finished frames.
 */
export function wrapStream(socket: Duplex, options: ChannelOptions): Promise<PqTlsStream>

/**
 * Wrap a WebSocket (native API or `ws` package) with a post-quantum secure
 * channel. Resolves once the handshake completes. If the handshake fails, the
 * WebSocket is closed before the promise rejects. A native WebSocket whose
 * `binaryType` is `'blob'` is switched to `'arraybuffer'`.
 */
export function wrapWebSocket(ws: unknown, options: ChannelOptions): Promise<PqTlsWebSocket>

/**
 * Encrypted WebSocket wrapper returned by `wrapWebSocket`.
 * Emits `message`, `close`, and `error` events.
 */
export declare class PqTlsWebSocket extends EventEmitter {
  /** The ML-DSA-65 public key the peer proved, or `undefined` without mutual authentication. */
  readonly peerPublicKey: Uint8Array | undefined
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
  /**
   * Present only where a caller may reasonably branch on the failure. Currently
   * the handshake deadline, `ERR_KXCO_PQ_TLS_HANDSHAKE_TIMEOUT`.
   */
  code?: string
}

/** `err.code` on a handshake that exceeded its deadline. */
export const ERR_HANDSHAKE_TIMEOUT: 'ERR_KXCO_PQ_TLS_HANDSHAKE_TIMEOUT'
