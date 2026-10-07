# kxco-pq-tls

**Hybrid ML-KEM-768 and X25519 encrypted channels for Node streams and WebSockets: a recorded session stays closed unless both are broken.**

[![npm](https://img.shields.io/npm/v/kxco-pq-tls?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-tls)
[![downloads](https://img.shields.io/npm/dm/kxco-pq-tls?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-pq-tls)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-pq-tls)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-tls)](https://socket.dev/npm/package/kxco-pq-tls)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-tls.svg)](https://nodejs.org)

Post-quantum encrypted channels for Node.js streams and WebSockets.

Wraps any duplex stream or WebSocket with hybrid ML-KEM-768 (NIST FIPS 203) and X25519 key exchange and AES-256-GCM records, with optional ML-DSA-87 or ML-DSA-65 (NIST FIPS 204) signatures from both sides over the handshake transcript.

- **Built for harvest-now, decrypt-later.** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks) names adversaries "collecting United States information now, and decrypting it later once large-scale quantum computers are operational". Every session key here comes from ML-KEM-768 and X25519 together, with no mode that drops either, so a recorded session stays closed unless both are broken.
- **Mutual authentication at ML-DSA-87.** Each end signs the handshake transcript with its own ML-DSA-87 or ML-DSA-65 key, and the two ends need not use the same set.
- **Separate keys each way, every record authenticated.** Per-direction AES-256-GCM keys and a sequence-number nonce on each record, so a tampered, replayed or reordered frame fails authentication.
- **A handshake completes or it reports.** `handshakeTimeoutMs` bounds the whole exchange, 30 seconds by default, and fails with a distinct error code, so a stalled peer cannot hold a connection open.
- **Versioned on the wire.** Both hellos open with a version byte and the key schedule is labelled `kxco-pq-tls-v1`, so a future handshake version is identifiable from its first byte.
- **One API for streams and WebSockets.** `wrapStream` for any Node `Duplex`, `wrapWebSocket` for the `ws` package or the native WebSocket API, and the handshake pair, `initiatorHandshake` and `responderHandshake`, for a transport of your own.
- **Proven underneath.** 1,793 NIST ACVP vectors passed, 0 failed, and 225 interoperability checks against liboqs, Bouncy Castle and the Python reference implementations, 0 failed, in [`kxco-post-quantum`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md).
- **A supply chain you can check.** SLSA provenance and a CycloneDX SBOM on every release since 1.1.1, third-party dependencies pinned to exact versions, and every GitHub Action pinned by commit SHA.

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [Handshake protocol](#handshake-protocol) · [For institutions](#for-institutions) · [TLS settings](./TLS.md) · [Assessment notes](./ASSESSMENT.md) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

## What this is for

**Post-quantum encryption over a channel you already have.** Two Node processes on a socket that is not HTTP. A WebSocket between two services you run. A duplex stream inside a private network. Give both ends an ML-DSA-87 identity and each signs the handshake transcript inside the encrypted session.

**For ordinary HTTPS traffic, use TLS with the standardised hybrid group.** OpenSSL 3.5 and Node 24.7+/22.20+ negotiate `X25519MLKEM768`, which gives you record-now-decrypt-later protection at the transport layer with a configuration change and no library at all. [`TLS.md`](TLS.md) has the exact settings for Node, nginx and OpenSSL, and the one command that proves the group was negotiated on the wire.

The two are complementary. TLS protects the channel and leaves nothing behind once it closes. This package brings the same hybrid key exchange, and ML-DSA-87 or ML-DSA-65 identity keys, to channels TLS does not reach.

## When to use this

- Institution-to-institution links between services you run on both ends
- Institution-to-user encrypted messaging over a WebSocket
- Channels where a recorded session must stay closed to a future quantum computer: X25519 and ML-KEM-768 are combined, so both must be broken to recover the session key

For encryption at rest, use [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault).

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

// Server: responder side
const server = net.createServer(async (socket) => {
  const channel = await wrapStream(socket, { role: 'responder' })
  channel.on('data', (buf) => {
    console.log('server received:', buf.toString())
    channel.write(Buffer.from('hello from server'))
  })
})
server.listen(4000)

// Client: initiator side
const socket = net.connect(4000)
const channel = await wrapStream(socket, { role: 'initiator' })
channel.on('data', (buf) => console.log('client received:', buf.toString()))
channel.write(Buffer.from('hello from client'))
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
  channel.on('message', (buf) => {
    console.log('server received:', buf.toString())
    channel.send(Buffer.from('hello from server'))
  })
})

// Client
const ws = new WebSocket('ws://localhost:4001')
ws.on('open', async () => {
  const channel = await wrapWebSocket(ws, { role: 'initiator' })
  channel.on('message', (buf) => console.log('client received:', buf.toString()))
  channel.send(Buffer.from('hello from client'))
})
```

### With mutual authentication

Both sides pass an ML-DSA keypair. Each signs the handshake transcript and checks the other's signature during the handshake, before any application data is exchanged.

ML-DSA-87 and ML-DSA-65 (NIST FIPS 204) are both supported, and each side's key sets its parameter set: a 2592-byte public key is ML-DSA-87 and a 1952-byte public key is ML-DSA-65. Any other length is refused with `KxcoPqTlsError`. Use ML-DSA-87 for new identities: it is the FIPS 204 parameter set at NIST security category 5, the highest. The two sides need not match, so a server can move to ML-DSA-87 while its clients still hold ML-DSA-65 keys, and the reverse. ML-DSA-87 on either side needs 1.3.0 or later at both ends; two ML-DSA-65 ends interoperate with 1.2.4.

```js
import net from 'node:net'
import { mlDsa87 } from 'kxco-post-quantum'
import { wrapStream } from 'kxco-pq-tls'

const serverIdentity = mlDsa87.ml_dsa87.keygen()
const clientIdentity = mlDsa87.ml_dsa87.keygen()

// Server
net.createServer(async (socket) => {
  const channel = await wrapStream(socket, { role: 'responder', identity: serverIdentity })
  channel.on('data', (buf) => console.log('server received:', buf.toString()))
}).listen(4002)

// Client
const channel = await wrapStream(net.connect(4002), { role: 'initiator', identity: clientIdentity })
channel.write(Buffer.from('hello from client'))
```

Mutual authentication is requested by the initiator, so give both sides an `identity`. A responder holding one refuses an initiator that has none, with `KxcoPqTlsError`, and closes the connection, so the initiator's handshake fails at once. An initiator holding one fails with `ERR_HANDSHAKE_TIMEOUT` when the responder does not answer with its own. A valid signature proves the peer holds the key it presented, not which key that is, so pass the key you expect as `peerPublicKey` to require it; `channel.peerPublicKey` reports the key the peer proved.

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

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

### `wrapStream(socket, options)` → `Promise<PqTlsStream>`

Wraps a Node.js `Duplex` stream (e.g. `net.Socket`) with a post-quantum secure channel. Resolves to an encrypted `Duplex` once the handshake completes. The returned stream behaves like a normal Node.js stream: `write`, `data` events, `end`.

```ts
interface ChannelOptions {
  role: 'initiator' | 'responder'
  identity?: { publicKey: Uint8Array, secretKey: Uint8Array }  // ML-DSA-87 or ML-DSA-65 keypair
  peerPublicKey?: Uint8Array    // ML-DSA-87 or ML-DSA-65 key the peer must prove; needs identity
  handshakeTimeoutMs?: number   // total handshake deadline, default 30000, 0 disables
}

interface PqTlsStream extends Duplex {
  readonly peerPublicKey: Uint8Array | undefined  // the key the peer proved
}

wrapStream(socket: Duplex, options: ChannelOptions): Promise<PqTlsStream>
```

#### The handshake deadline

A handshake is four small messages and a few milliseconds of arithmetic, so it
runs long only when the peer is never going to answer. One case makes that easy
to hit by accident: **an initiator configured with an `identity` expects a
`Finished` frame, and a responder with no identity of its own never sends one.** Both ends
believe they are correctly configured, the responder completes, and the
initiator waits. The reverse mismatch fails at once: a responder holding an
identity refuses an initiator without one.

`recv` belongs to the caller, so the package bounds that wait itself. The
deadline defaults to 30 seconds and fails with a distinguishable error:

```js
import { wrapStream, ERR_HANDSHAKE_TIMEOUT } from 'kxco-pq-tls'

try {
  const secure = await wrapStream(socket, { role: 'initiator', identity })
} catch (err) {
  if (err.code === ERR_HANDSHAKE_TIMEOUT) {
    // The peer accepted the connection and then did not send the expected
    // frame. Usually a configuration mismatch: this side has an identity and
    // the peer does not.
  }
}
```

The deadline covers the handshake as a whole rather than each message, so a peer
that dribbles bytes cannot hold the connection open by resetting a per-message
timer. Pass `handshakeTimeoutMs: 0` to wait without a deadline.

### `wrapWebSocket(ws, options)` → `Promise<PqTlsWebSocket>`

Wraps a WebSocket with a post-quantum secure channel. Compatible with the `ws` npm package (Node.js) and the native `WebSocket` API (Cloudflare Workers, browsers, Node.js 22+). Resolves to a `PqTlsWebSocket` once the handshake completes.

```ts
wrapWebSocket(ws: unknown, options: ChannelOptions): Promise<PqTlsWebSocket>
```

### `PqTlsWebSocket`

Returned by `wrapWebSocket`. Extends `EventEmitter`.

```ts
class PqTlsWebSocket extends EventEmitter {
  readonly peerPublicKey: Uint8Array | undefined  // the key the peer proved
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
  peerPublicKey: Uint8Array | undefined  // the key the peer proved, if mutual
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
  [1]    flags   (bit 0 = mutual_auth_requested,
                  bit 1 = the initiator signs with ML-DSA-87)
  [1184] ML-KEM-768 ephemeral encapsulation key
  [32]   X25519 ephemeral public key

ServerHello (1122 bytes):
  [1]    version = 0x01
  [1]    flags   (bits 0 and 1 echo the ClientHello,
                  bit 2 = the responder signs with ML-DSA-87)
  [1088] ML-KEM-768 ciphertext
  [32]   X25519 ephemeral public key

Session keys: HKDF(ss_kem || ss_dh, salt = c_x25519_pk || s_x25519_pk, info = "kxco-pq-tls-v1")
```

If mutual authentication is requested, both sides exchange a `Finished` frame (encrypted under the new session keys) containing their ML-DSA public key and a signature over `SHA-256(label || SHA-256(clientHello || serverHello))`, where the label is `kxco-pq-tls-v1-finished-initiator` or `kxco-pq-tls-v1-finished-responder` for the side that signs. A responder holding an identity refuses a ClientHello that does not request it.

Each side declares its parameter set in the hello it sends, so the peer knows the size of the `Finished` frame before it decrypts it: 7220 bytes for ML-DSA-87 and 5262 for ML-DSA-65, plus a 16-byte tag. Both hellos are inside the signed transcript, so each signature also covers the set each side declared. A `Finished` frame of the wrong size for its sender's declared set is refused, a pinned `peerPublicKey` fixes the set the peer must declare, and a hello carrying a flag this version does not know is refused. With ML-DSA-65 at both ends the set flags are clear and every message has the layout and flags 1.2.4 sends.

Session encryption uses AES-256-GCM with a per-message sequence number as the nonce. After mutual authentication the Finished frames take sequence 0 in each direction and records start at 1, so no nonce repeats under a key.

## The KXCO post-quantum family

This package encrypts channels between systems you run. The rest of the family
covers the jobs around it:

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

## Release integrity

Every release since 1.1.0 carries a SLSA provenance attestation tying the published tarball to
the commit and workflow that built it: verify with `npm audit signatures`, or read
it from `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-tls@<version>`. A CycloneDX
SBOM is published, from v1.1.1, as a GitHub Release asset at
`releases/download/v<version>/sbom.cyclonedx.json`, a permanent unauthenticated
URL. Sibling `kxco-*` packages sit on caret ranges so a correctness fix in the
base package reaches you on the next install, with no release of every package
above it.

## Security

**ML-DSA-87**, **ML-DSA-65** (NIST FIPS 204) and **ML-KEM-768** (NIST FIPS 203) via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them. X25519, HKDF and AES-256-GCM come from `@noble/curves`, `@noble/hashes` and `@noble/ciphers`, pinned to exact versions. No custom primitives.

Evidenced, and reproducible on your own machine:

- **1,793 NIST ACVP vectors passed, 0 failed** across FIPS 203, 204 and 205, pinned by digest, per [CONFORMANCE.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md). The other 310 are pairings the library refuses as weaker than the parameter set
- **225 interoperability checks passed, 0 failed**, against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every release since 1.1.0: verify with `npm audit signatures`
- **CycloneDX SBOM** published with every release since 1.1.1
- `npm run evidence` regenerates the whole bundle from source

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

Key exchange combines ML-KEM-768 with X25519: an adversary who breaks X25519 still cannot recover the session key. For post-quantum transport on public endpoints, see [`TLS.md`](TLS.md), where OpenSSL 3.5 negotiates the standardised `X25519MLKEM768` hybrid group.

## License

Apache-2.0 © 2026 Knightsbridge Financial Ltd, trading as KXCO. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Maintainers

Shayne Heffernan and John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
