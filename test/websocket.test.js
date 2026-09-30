/**
 * End-to-end tests for wrapWebSocket over real WebSocket connections on
 * localhost. The server end, and the client end where noted, is a minimal
 * RFC 6455 endpoint written here with the `ws` package's event API, so the
 * suite needs no dependency. Like `ws`, it emits every frame a TCP chunk
 * carries in the same turn. Where the runtime has a global WebSocket, one test
 * also uses it as the client, through the native event API.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import crypto from 'node:crypto'
import { EventEmitter } from 'node:events'
import { mlDsa } from 'kxco-post-quantum'
import { wrapWebSocket } from '../src/websocket.js'
import { KxcoPqTlsError } from '../src/errors.js'

const initId = mlDsa.ml_dsa65.keygen()
const respId = mlDsa.ml_dsa65.keygen()
const otherId = mlDsa.ml_dsa65.keygen()

const sameKey = (reported, publicKey) =>
  reported !== undefined && Buffer.from(reported).equals(Buffer.from(publicKey))

const outcome = (p) => p.then((value) => ({ value }), (error) => ({ error }))

async function within(ms, what, promise) {
  let timer
  const late = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`stalled: ${what}`)), ms)
  })
  try {
    return await Promise.race([promise, late])
  } finally {
    clearTimeout(timer)
  }
}

const nextMessage = (channel) => new Promise((res) => channel.once('message', res))

// ---------------------------------------------------------------------------
// A minimal WebSocket endpoint: binary frames, unfragmented, no extensions.
// ---------------------------------------------------------------------------

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

class MiniWebSocket extends EventEmitter {
  constructor(socket, head, isClient) {
    super()
    this.readyState = 1
    this._socket = socket
    this._isClient = isClient   // a client masks what it sends
    this._buf = Buffer.from(head)
    socket.on('data', (chunk) => this._onData(chunk))
    socket.on('close', () => { this.readyState = 3; this.emit('close', 1006, Buffer.alloc(0)) })
    socket.on('error', (err) => this.emit('error', err))
  }

  _onData(chunk) {
    this._buf = Buffer.concat([this._buf, chunk])
    for (;;) {
      const b = this._buf
      if (b.length < 2) return
      let len = b[1] & 0x7f
      let at = 2
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); at = 4 }
      if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); at = 10 }
      const masked = (b[1] & 0x80) !== 0
      if (b.length < at + (masked ? 4 : 0) + len) return
      const mask = masked ? b.subarray(at, at + 4) : null
      if (masked) at += 4
      const payload = Buffer.from(b.subarray(at, at + len))
      if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3]
      this._buf = b.subarray(at + len)
      const opcode = b[0] & 0x0f
      if (opcode === 0x8) { this.close(); return }
      if (opcode === 0x1 || opcode === 0x2) this.emit('message', payload, opcode === 0x2)
    }
  }

  _frame(opcode, data) {
    const payload = Buffer.from(data)
    let head
    if (payload.length < 126) {
      head = Buffer.from([0x80 | opcode, payload.length])
    } else if (payload.length < 65536) {
      head = Buffer.alloc(4)
      head[0] = 0x80 | opcode; head[1] = 126; head.writeUInt16BE(payload.length, 2)
    } else {
      head = Buffer.alloc(10)
      head[0] = 0x80 | opcode; head[1] = 127; head.writeBigUInt64BE(BigInt(payload.length), 2)
    }
    if (!this._isClient) return Buffer.concat([head, payload])
    head[1] |= 0x80
    const mask = crypto.randomBytes(4)
    for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3]
    return Buffer.concat([head, mask, payload])
  }

  send(data, cb) { this._socket.write(this._frame(0x2, data), cb) }

  close() {
    if (this._socket.writable) this._socket.end(this._frame(0x8, Buffer.alloc(0)))
  }
}

// A WebSocket server on localhost that accepts one connection. Resolves with
// the port and a promise for the server end. Closed when the test ends.
function wsServer(t) {
  return new Promise((resolve) => {
    let accept
    const accepted = new Promise((res) => { accept = res })
    const server = http.createServer()
    const sockets = []
    server.on('upgrade', (req, socket, head) => {
      sockets.push(socket)
      const key = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + GUID).digest('base64')
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${key}\r\n\r\n`,
      )
      accept(new MiniWebSocket(socket, head, false))
    })
    t.after(() => { for (const s of sockets) s.destroy(); server.close() })
    server.listen(0, '127.0.0.1', () => resolve({ port: server.address().port, accepted }))
  })
}

// Both ends as MiniWebSocket over one real connection.
async function wsPair(t) {
  const { port, accepted } = await wsServer(t)
  const client = await new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port,
      headers: {
        Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': crypto.randomBytes(16).toString('base64'),
      },
    })
    req.on('upgrade', (_res, socket, head) => {
      t.after(() => socket.destroy())
      resolve(new MiniWebSocket(socket, head, true))
    })
    req.on('error', reject)
    req.end()
  })
  return [client, await accepted]
}

// ---------------------------------------------------------------------------
// Messages that arrive together
// ---------------------------------------------------------------------------

test('wrapWebSocket: a message the responder sends straight after the handshake arrives', async (t) => {
  const [c, s] = await wsPair(t)
  const [client] = await Promise.all([
    wrapWebSocket(c, { role: 'initiator', handshakeTimeoutMs: 3000 }),
    wrapWebSocket(s, { role: 'responder', handshakeTimeoutMs: 3000 })
      .then((server) => server.send(Buffer.from('first word from server'))),
  ])
  const msg = await within(3000, 'no message reached the client', nextMessage(client))
  assert.equal(msg.toString(), 'first word from server')
})

test('wrapWebSocket: mutual authentication, each side reporting the key the other proved', async (t) => {
  // The responder sends its ServerHello and Finished back to back, then speaks first.
  const [c, s] = await wsPair(t)
  const [client, server] = await Promise.all([
    wrapWebSocket(c, { role: 'initiator', identity: initId, handshakeTimeoutMs: 3000 }),
    wrapWebSocket(s, { role: 'responder', identity: respId, handshakeTimeoutMs: 3000 })
      .then((server) => { server.send(Buffer.from('greeting')); return server }),
  ])
  assert.ok(sameKey(client.peerPublicKey, respId.publicKey), 'the client reports the server key')
  assert.ok(sameKey(server.peerPublicKey, initId.publicKey), 'the server reports the client key')

  const greeting = await within(3000, 'no greeting', nextMessage(client))
  assert.equal(greeting.toString(), 'greeting')
  client.send(Buffer.from('reply'))
  const reply = await within(3000, 'no reply', nextMessage(server))
  assert.equal(reply.toString(), 'reply')
})

test('wrapWebSocket: mutual authentication with a native WebSocket client', {
  skip: typeof globalThis.WebSocket !== 'function' && 'this runtime has no global WebSocket',
}, async (t) => {
  const { port, accepted } = await wsServer(t)
  const native = new globalThis.WebSocket(`ws://127.0.0.1:${port}`)
  native.binaryType = 'arraybuffer'
  await new Promise((res, rej) => {
    native.addEventListener('open', res, { once: true })
    native.addEventListener('error', rej, { once: true })
  })
  const [client, server] = await Promise.all([
    wrapWebSocket(native, { role: 'initiator', identity: initId, handshakeTimeoutMs: 3000 }),
    accepted.then((s) => wrapWebSocket(s, { role: 'responder', identity: respId, handshakeTimeoutMs: 3000 }))
      .then((server) => { server.send(Buffer.from('greeting')); return server }),
  ])
  assert.ok(sameKey(client.peerPublicKey, respId.publicKey), 'the client reports the server key')
  assert.ok(sameKey(server.peerPublicKey, initId.publicKey), 'the server reports the client key')
  const greeting = await within(3000, 'no greeting', nextMessage(client))
  assert.equal(greeting.toString(), 'greeting')

  const closed = new Promise((res) => native.addEventListener('close', res, { once: true }))
  client.close()
  await closed
})

// ---------------------------------------------------------------------------
// Peer identity
// ---------------------------------------------------------------------------

test('wrapWebSocket: a pinned peer key that does not match fails the handshake', async (t) => {
  const [c, s] = await wsPair(t)
  const [client] = await Promise.all([
    outcome(wrapWebSocket(c, {
      role: 'initiator', identity: initId, peerPublicKey: otherId.publicKey, handshakeTimeoutMs: 3000,
    })),
    outcome(wrapWebSocket(s, { role: 'responder', identity: respId, handshakeTimeoutMs: 3000 })),
  ])
  assert.ok(client.error instanceof KxcoPqTlsError, 'the client refuses')
  assert.match(client.error.message, /pinned peerPublicKey/)
})

test('wrapWebSocket: a responder holding an identity refuses an initiator without one', async (t) => {
  const [c, s] = await wsPair(t)
  const [client, server] = await Promise.all([
    outcome(wrapWebSocket(c, { role: 'initiator', handshakeTimeoutMs: 3000 })),
    // A server that closes the connection when its handshake fails.
    outcome(wrapWebSocket(s, { role: 'responder', identity: respId, handshakeTimeoutMs: 3000 })
      .catch((err) => { s.close(); throw err })),
  ])
  assert.ok(server.error instanceof KxcoPqTlsError, 'the server refuses')
  assert.match(server.error.message, /did not request mutual authentication/)
  // The close reaches the client while it waits for the ServerHello.
  assert.ok(client.error instanceof KxcoPqTlsError, 'the client does not complete')
  assert.match(client.error.message, /closed during handshake/)
})
