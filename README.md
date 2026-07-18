# kxco-pq-tls

[![npm](https://img.shields.io/npm/v/kxco-pq-tls?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-tls)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-tls)](https://socket.dev/npm/package/kxco-pq-tls)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-tls.svg)](https://nodejs.org)

Post-quantum encrypted channels for Node.js streams and WebSockets.

Wraps any duplex stream or WebSocket with ML-KEM-768 key exchange (NIST FIPS 203) and ML-DSA-65 mutual authentication (NIST FIPS 204). Both sides authenticate each other during the handshake — no anonymous connections.

## When to use this

- Institution-to-institution communication where both endpoints must prove identity before data flows
- Institution-to-user encrypted messaging where a client authenticates to a server with a PQ identity key
- Any scenario where TLS alone is not quantum-safe — TLS 1.3 uses X25519, which a sufficiently powerful quantum computer could break; this package combines X25519 with ML-KEM-768 so both must be broken simultaneously

If you need quantum-safe encryption at rest rather than in transit, use `kxco-pq-vault`.

## Install

```
npm install kxco-pq-tls
```

Requires Node.js 20.19 or later.

## Quick start

### Node.js TCP streams

```js
import net from 'node:net'
import { wrapStream } from 'kxco-pq-tls'

// Server — responder side
const server = net.createServer(async (socket) => {
  const channel = await wrapStream(socket, { role: 'responder' })
  channel.on('data', (buf) => console.log('server received:', buf.toString()))
  channel.write(Buffer.from('hello from server'))
})
server.listen(4000)

// Client — initiator side
const socket = net.connect(4000)
const channel = await wrapStream(socket, { role: 'initiator' })
channel.write(Buffer.from('hello from client'))
channel.on('data', (buf) => console.log('client received:', buf.toString()))
```

### WebSocket (ws package or native WebSocket API)

```js
import { WebSocketServer } from 'ws'
import WebSocket from 'ws'
import { wrapWebSocket } from 'kxco-pq-tls'

// Server
const wss = new WebSocketServer({ port: 4001 })
wss.on('connection', async (ws) => {
  const channel = await wrapWebSocket(ws, { role: 'responder' })
  channel.on('message', (buf) => console.log('server received:', buf.toString()))
  channel.send(Buffer.from('hello from server'))
})

// Client
const ws = new WebSocket('ws://localhost:4001')
ws.on('open', async () => {
  const channel = await wrapWebSocket(ws, { role: 'initiator' })
  channel.send(Buffer.from('hello from client'))
  channel.on('message', (buf) => console.log('client received:', buf.toString()))
})
```

### With mutual authentication

Both sides pass an ML-DSA-65 keypair. The identity is verified during the handshake, before any application data is exchanged.

```js
import { mlDsa } from 'kxco-post-quantum'
import { wrapStream } from 'kxco-pq-tls'

const serverIdentity = mlDsa.ml_dsa65.keygen()
const clientIdentity = mlDsa.ml_dsa65.keygen()

// Server
const channel = await wrapStream(socket, { role: 'responder', identity: serverIdentity })

// Client
const channel = await wrapStream(socket, { role: 'initiator', identity: clientIdentity })
```

If either side passes an `identity` and the peer does not, the handshake fails.

## API

```ts
import {
  wrapStream,
  wrapWebSocket,
  initiatorHandshake,
  responderHandshake,
  PqTlsWebSocket,
  KxcoPqTlsError,
} from 'kxco-pq-tls'
```

### `wrapStream(socket, options)` → `Promise<Duplex>`

Wraps a Node.js `Duplex` stream (e.g. `net.Socket`) with a post-quantum secure channel. Resolves to an encrypted `Duplex` once the handshake completes. The returned stream behaves like a normal Node.js stream — `write`, `data` events, `end`.

```ts
interface ChannelOptions {
  role: 'initiator' | 'responder'
  identity?: { publicKey: Uint8Array, secretKey: Uint8Array }  // ML-DSA-65 keypair
}

wrapStream(socket: Duplex, options: ChannelOptions): Promise<Duplex>
```

### `wrapWebSocket(ws, options)` → `Promise<PqTlsWebSocket>`

Wraps a WebSocket with a post-quantum secure channel. Compatible with the `ws` npm package (Node.js) and the native `WebSocket` API (Cloudflare Workers, browsers, Node.js 22+). Resolves to a `PqTlsWebSocket` once the handshake completes.

```ts
wrapWebSocket(ws: unknown, options: ChannelOptions): Promise<PqTlsWebSocket>
```

### `PqTlsWebSocket`

Returned by `wrapWebSocket`. Extends `EventEmitter`.

```ts
class PqTlsWebSocket extends EventEmitter {
  send(data: string | Buffer | Uint8Array): void
  close(code?: number, reason?: string | Buffer): void
}
```

Emits: `message` (Buffer), `close` (code, reason), `error` (Error).

### `initiatorHandshake(send, recv, options?)` → `Promise<SessionKeys>`

Low-level API. Run the initiator side of the handshake over custom send/recv functions. Use this when you are bringing your own transport.

```ts
type SendFn = (data: Buffer) => Promise<void>
type RecvFn = (n: number)   => Promise<Buffer>

interface SessionKeys {
  txKey: Uint8Array  // initiator → responder encryption key
  rxKey: Uint8Array  // responder → initiator encryption key
}

initiatorHandshake(send: SendFn, recv: RecvFn, options?: HandshakeOptions): Promise<SessionKeys>
```

### `responderHandshake(send, recv, options?)` → `Promise<SessionKeys>`

Low-level API. Run the responder side of the handshake. Returns `txKey` (responder→initiator) and `rxKey` (initiator→responder).

```ts
responderHandshake(send: SendFn, recv: RecvFn, options?: HandshakeOptions): Promise<SessionKeys>
```

### `KxcoPqTlsError`

Thrown on handshake failure, authentication failure, or malformed frames.

## Handshake protocol

```
ClientHello (1218 bytes):
  [1]    version = 0x01
  [1]    flags   (bit 0 = mutual_auth_requested)
  [1184] ML-KEM-768 ephemeral encapsulation key
  [32]   X25519 ephemeral public key

ServerHello (1122 bytes):
  [1]    version = 0x01
  [1]    flags
  [1088] ML-KEM-768 ciphertext
  [32]   X25519 ephemeral public key

Session keys: HKDF(ss_kem || ss_dh, salt = c_x25519_pk || s_x25519_pk, info = "kxco-pq-tls-v1")
```

If mutual authentication is requested, both sides exchange a `Finished` frame (encrypted under the new session keys) containing their ML-DSA-65 public key and a signature over `SHA-256(clientHello || serverHello)`.

Session encryption uses AES-256-GCM with a per-message sequence number as the nonce.

## What this does NOT do

**Not a replacement for HTTPS/TLS on public servers.** If you are running an HTTP server and want quantum-safe transport to browsers, put a PQ-capable reverse proxy (e.g. Cloudflare) in front of it. This package secures the channel between two Node.js processes that both run this code.

**Not encryption at rest.** For quantum-safe encryption of stored data or blobs, use `kxco-pq-vault`.

**Not a certificate authority.** This package does not manage or rotate long-lived identity keys. Key generation and storage is your responsibility — use `kxco-pq-hsm` if you need HSM-backed key management.

## Security

Key exchange uses [Noble post-quantum](https://github.com/paulmillr/noble-post-quantum) ML-KEM-768 combined with X25519 from [Noble curves](https://github.com/paulmillr/noble-curves). Session encryption uses AES-256-GCM from [Noble ciphers](https://github.com/paulmillr/noble-ciphers). All Noble libraries are independently audited by Cure53 (2024). A quantum adversary who breaks X25519 still cannot break the ML-KEM-768 component; both must be broken simultaneously.

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-tls/security/advisories/new) or email **security@kxco.ai**.

## Part of the KXCO stack

| Package | Role |
|---|---|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | ML-KEM-768 / ML-DSA-65 primitives (NIST FIPS 203 / 204) |
| [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) | Encrypted channels for streams and WebSockets |
| [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) | HSM-backed key management |
| [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) | Payload attestation envelopes |
| [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) | Integration layer |

## License

Apache-2.0 © 2026 KXCO by Knightsbridge

## Authors

Shayne Heffernan and John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
