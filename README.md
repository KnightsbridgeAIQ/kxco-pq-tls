# kxco-pq-tls

Hybrid post-quantum secure channels: ML-KEM-768 + X25519 key exchange, AES-256-GCM data encryption. Wraps Node.js streams and Cloudflare Workers WebSockets. Drop-in quantum-safe channel layer.

## Install

```
npm install kxco-pq-tls
```

## Quick start — Node.js streams

```js
import net from 'node:net'
import { wrapStream } from 'kxco-pq-tls'

// Server
const server = net.createServer(async (socket) => {
  const channel = await wrapStream(socket, 'responder')
  channel.on('data', buf => console.log('received:', buf.toString()))
  channel.write(Buffer.from('hello from server'))
})
server.listen(4000)

// Client
const socket = net.connect(4000)
const channel = await wrapStream(socket, 'initiator')
channel.write(Buffer.from('hello from client'))
```

## Quick start — Cloudflare Workers WebSocket

```js
import { wrapWebSocket } from 'kxco-pq-tls'

// Server worker
export default {
  async fetch(req) {
    const [client, server] = Object.values(new WebSocketPair())
    const channel = await wrapWebSocket(server, 'responder')
    channel.addEventListener('message', e => console.log(e.data))
    return new Response(null, { status: 101, webSocket: client })
  }
}
```

## Mutual authentication

Both sides can prove identity using ML-DSA-65 keypairs. The identity is verified during the handshake — before any application data is exchanged.

```js
import { mlDsa } from 'kxco-post-quantum'

const identity = mlDsa.ml_dsa65.keygen()

// Pass identity to either wrapStream or initiatorHandshake/responderHandshake
const channel = await wrapStream(socket, 'initiator', { identity })
```

## Handshake protocol

```
ClientHello (1218 bytes):
  [1]    version = 0x01
  [1]    flags   (bit 0 = mutual_auth_requested)
  [1184] ML-KEM-768 ephemeral encap key
  [32]   X25519 ephemeral public key

ServerHello (1122 bytes):
  [1]    version = 0x01
  [1]    flags
  [1088] ML-KEM-768 ciphertext
  [32]   X25519 ephemeral public key

Session keys: HKDF(ss_kem || ss_dh, salt=c_x25519_pk||s_x25519_pk, info="kxco-pq-tls-v1")
```

If mutual auth is requested, both sides exchange a `Finished` frame (encrypted over the new session keys) containing their ML-DSA-65 public key and a signature over `SHA-256(clientHello || serverHello)`.

## API

```js
import { wrapStream, wrapWebSocket, initiatorHandshake, responderHandshake } from 'kxco-pq-tls'

// High-level
const channel = await wrapStream(nodeStream, 'initiator' | 'responder', options?)
const channel = await wrapWebSocket(ws, 'initiator' | 'responder', options?)

// Low-level (bring your own send/recv)
const { txKey, rxKey } = await initiatorHandshake(send, recv, options?)
const { txKey, rxKey } = await responderHandshake(send, recv, options?)

// options: { identity?: { publicKey, secretKey } }  — ML-DSA-65 keypair for mutual auth
```

## Related packages

| Package | Role |
|---|---|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | ML-KEM-768 / ML-DSA-65 primitives |
| [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) | HSM-backed key management |
| [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) | Payload attestation envelopes |
| [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) | Integration layer |

## License

Apache-2.0 © 2026 KXCO by Knightsbridge

## Maintainers

Shayne Heffernan · John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
