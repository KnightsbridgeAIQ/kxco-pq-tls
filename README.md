# kxco-pq-tls

[![npm](https://img.shields.io/npm/v/kxco-pq-tls?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-tls)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-tls)](https://socket.dev/npm/package/kxco-pq-tls)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-tls.svg)](https://nodejs.org)

Post-quantum encrypted channels for Node.js streams and WebSockets.

Wraps any duplex stream or WebSocket with ML-KEM-768 key exchange (NIST FIPS 203) and ML-DSA-65 mutual authentication (NIST FIPS 204). Both sides authenticate each other during the handshake — no anonymous connections.

## What this is for

**Mutual ML-DSA-65 identity over a channel you already have.** Two Node processes on a socket that is not HTTP. A WebSocket where both ends must prove which key they hold, not merely which certificate a CA signed. A duplex stream inside a private network. Both sides authenticate during the handshake — there are no anonymous connections.

**For ordinary HTTPS traffic, use TLS with the standardised hybrid group.** OpenSSL 3.5 and Node 24.7+/22.20+ negotiate `X25519MLKEM768`, which gives you record-now-decrypt-later protection at the transport layer with a configuration change and no library at all. [`TLS.md`](TLS.md) has the exact settings for Node, nginx and OpenSSL, and — the part most guides omit — the one command that proves the group was actually negotiated rather than silently skipped.

The two are complementary. TLS protects the channel and leaves nothing behind once it closes. This package proves *which key* is at the other end, on a channel TLS does not reach.

## Release integrity

Every release of this package is checkable without asking us for anything.

- **Provenance.** Each release carries a SLSA provenance attestation tying the
  published tarball to the commit and workflow that built it. Verify with
  `npm audit signatures`, or read it directly from
  `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-tls@<version>`.
- **Bill of materials.** A CycloneDX SBOM is published as a GitHub Release asset
  at `releases/download/v<version>/sbom.cyclonedx.json`, a permanent
  unauthenticated URL. Not an expiring build artifact.
- **Pinned where it matters.** Third-party dependencies are pinned to exact
  versions, never ranges, so the code that performs the cryptography cannot
  change without a release. Sibling `kxco-*` packages sit on caret ranges
  deliberately: it means a correctness fix in the base package reaches you
  without a release of every package above it. That is not theoretical. When
  `@noble/post-quantum` 0.7.1 was found to fail NIST SLH-DSA verification
  vectors, the revert in the base package propagated here on the next install.
  Every GitHub Action is pinned by 40-character commit SHA.
- **Conformance underneath.** The cryptography comes from
  [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
  is run against **2,103 NIST ACVP vectors: 1,793 passed, 0 failed, 310 skipped** and a **225-check
  cross-implementation interoperability matrix** against liboqs, Bouncy Castle
  and two pure-Python implementations, in both directions and with negative
  controls. Its published tarball also rebuilds bit-for-bit from its own tag,
  verified in CI on every run.

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
  handshakeTimeoutMs?: number   // total handshake deadline, default 30000, 0 disables
}

wrapStream(socket: Duplex, options: ChannelOptions): Promise<Duplex>
```

#### The handshake deadline

A handshake is four small messages and a few milliseconds of arithmetic, so it
runs long only when the peer is never going to answer. One case makes that easy
to hit by accident: **a side configured with an `identity` expects a `Finished`
frame, and a peer with no identity of its own never sends one.** Both ends
believe they are correctly configured, the responder completes, and the
initiator waits.

`recv` belongs to the caller, so before this option nothing in this package
could bound that wait. It now defaults to 30 seconds and fails with a
distinguishable error:

```js
import { wrapStream, ERR_HANDSHAKE_TIMEOUT } from 'kxco-pq-tls'

try {
  const secure = await wrapStream(socket, { role: 'initiator', identity })
} catch (err) {
  if (err.code === ERR_HANDSHAKE_TIMEOUT) {
    // The peer is unreachable, is not speaking this protocol, or was not
    // configured with an identity while this side was.
  }
}
```

The deadline covers the handshake as a whole rather than each message, so a peer
that dribbles bytes cannot hold the connection open by resetting a per-message
timer. Pass `handshakeTimeoutMs: 0` for the previous unbounded behaviour.

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

## Where this fits

Quantum-safe channels between systems you control: Node.js streams and
WebSockets, with ML-KEM-768 key exchange and optional ML-DSA-65 mutual
authentication.

**For a public HTTPS server**, terminate TLS 1.3 with the `X25519MLKEM768`
hybrid group at your edge; `TLS.md` has the configuration and how to prove it
is on the wire.

- [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) for data at rest
- [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) for long-lived identity keys

## Security

**ML-DSA-65** (NIST FIPS 204) and **ML-KEM-768** (NIST FIPS 203) via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them. No custom cryptography.

Evidenced, and reproducible on your own machine:

- **2,103 NIST ACVP vectors** across FIPS 203, 204 and 205, pinned by digest: 1,793 passed, 0 failed, 310 skipped, where each skip is the library refusing a pre-hash weaker than the parameter set
- **225 interoperability checks passed, 0 failed, 42 not applicable** against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every published release — verify with `npm audit signatures`
- **CycloneDX SBOM** published with each release
- `npm run evidence` regenerates the whole bundle from source

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

Key exchange combines ML-KEM-768 with X25519: an adversary who breaks X25519 still cannot recover the session key. For post-quantum transport on public endpoints, see [`TLS.md`](TLS.md) — OpenSSL 3.5 negotiates the standardised `X25519MLKEM768` hybrid group.

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
