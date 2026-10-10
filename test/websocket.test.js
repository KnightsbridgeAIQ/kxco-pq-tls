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
import { mlDsa, mlDsa87 } from 'kxco-post-quantum'
import { wrapWebSocket } from '../src/websocket.js'
import { KxcoPqTlsError, ERR_HANDSHAKE_TIMEOUT, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024 } from '../src/errors.js'
// The release on npm before ML-KEM-1024, unmodified.
import * as v140 from 'kxco-pq-tls-140'
// The last release before responders checked hello flags, unmodified.
import * as v124 from 'kxco-pq-tls-124'
// The last release before a failed handshake closed the WebSocket, unmodified.
import * as v123 from 'kxco-pq-tls-123'

const initId = mlDsa.ml_dsa65.keygen()
const respId = mlDsa.ml_dsa65.keygen()
const otherId = mlDsa.ml_dsa65.keygen()
const initId87 = mlDsa87.ml_dsa87.keygen()
const respId87 = mlDsa87.ml_dsa87.keygen()

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

test('wrapWebSocket: ML-DSA-87 at both ends, and mixed with ML-DSA-65 in either role', async (t) => {
  for (const [label, i, r] of [
    ['ML-DSA-87 to ML-DSA-87', initId87, respId87],
    ['ML-DSA-87 to ML-DSA-65', initId87, respId],
    ['ML-DSA-65 to ML-DSA-87', initId, respId87],
  ]) {
    const [c, s] = await wsPair(t)
    const [client, server] = await Promise.all([
      wrapWebSocket(c, { role: 'initiator', identity: i, peerPublicKey: r.publicKey, handshakeTimeoutMs: 3000 }),
      wrapWebSocket(s, { role: 'responder', identity: r, peerPublicKey: i.publicKey, handshakeTimeoutMs: 3000 })
        .then((server) => { server.send(Buffer.from('greeting')); return server }),
    ])
    assert.ok(sameKey(client.peerPublicKey, r.publicKey), `${label}: the client reports the server key`)
    assert.ok(sameKey(server.peerPublicKey, i.publicKey), `${label}: the server reports the client key`)

    const greeting = await within(3000, `${label}: no greeting`, nextMessage(client))
    assert.equal(greeting.toString(), 'greeting')
    client.send(Buffer.from('reply'))
    const reply = await within(3000, `${label}: no reply`, nextMessage(server))
    assert.equal(reply.toString(), 'reply')
  }
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
  // The close reaches the client while it waits for the ServerHello. On
  // ML-KEM-1024, the default, the client names an older responder as the
  // likely reason, and keeps the close as the cause.
  assert.ok(client.error instanceof KxcoPqTlsError, 'the client does not complete')
  assert.equal(client.error.code, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024)
  assert.match(client.error.message, /^the responder closed after an ML-KEM-1024 hello/)
  assert.match(client.error.cause?.message ?? '', /closed during handshake/)
})

test('wrapWebSocket: a native WebSocket left at its default binaryType completes the handshake', {
  skip: typeof globalThis.WebSocket !== 'function' && 'this runtime has no global WebSocket',
}, async (t) => {
  // A native WebSocket delivers binary messages as a Blob unless told otherwise.
  const { port, accepted } = await wsServer(t)
  const native = new globalThis.WebSocket(`ws://127.0.0.1:${port}`)
  await new Promise((res, rej) => {
    native.addEventListener('open', res, { once: true })
    native.addEventListener('error', rej, { once: true })
  })
  const [client] = await Promise.all([
    wrapWebSocket(native, { role: 'initiator', handshakeTimeoutMs: 3000 }),
    accepted.then((s) => wrapWebSocket(s, { role: 'responder', handshakeTimeoutMs: 3000 }))
      .then((server) => server.send(Buffer.from('greeting'))),
  ])
  const greeting = await within(3000, 'no greeting', nextMessage(client))
  assert.equal(greeting.toString(), 'greeting')
  assert.equal(native.binaryType, 'arraybuffer')

  const closed = new Promise((res) => native.addEventListener('close', res, { once: true }))
  client.close()
  await closed
})

// ---------------------------------------------------------------------------
// A failed handshake closes the WebSocket
// ---------------------------------------------------------------------------

test('wrapWebSocket: a refused initiator sees the WebSocket close at once, not at its deadline', async (t) => {
  // No application code closes anything here: the responder's own failure does.
  const [c, s] = await wsPair(t)
  const started = Date.now()
  const [client, server] = await Promise.all([
    outcome(wrapWebSocket(c, { role: 'initiator', handshakeTimeoutMs: 5000 })),
    outcome(wrapWebSocket(s, { role: 'responder', identity: respId, handshakeTimeoutMs: 5000 })),
  ])
  const elapsed = Date.now() - started
  assert.ok(server.error instanceof KxcoPqTlsError, 'the server refuses')
  assert.ok(client.error instanceof KxcoPqTlsError, 'the client does not complete')
  assert.equal(client.error.code, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024)
  assert.match(client.error.message, /^the responder closed after an ML-KEM-1024 hello/)
  assert.match(client.error.cause?.message ?? '', /closed during handshake/)
  assert.ok(elapsed < 2000, `the client waited ${elapsed}ms`)
})

test('wrapWebSocket: a handshake that runs out of time closes the WebSocket', async (t) => {
  // The server end never answers. An ML-KEM-768 initiator reports the plain
  // timeout; on ML-KEM-1024, the default, the deadline names the likely cause
  // and keeps the timeout as cause.
  for (const kem of [{ kem: 'ml-kem-768' }, {}]) {
    const [c, s] = await wsPair(t)
    const closed = new Promise((res) => s.once('close', res))
    const err = await wrapWebSocket(c, { role: 'initiator', handshakeTimeoutMs: 200, ...kem }).then(
      () => { throw new Error('expected a timeout') }, (e) => e)
    if (kem.kem) {
      assert.equal(err.code, ERR_HANDSHAKE_TIMEOUT)
    } else {
      assert.equal(err.code, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024)
      assert.equal(err.cause?.code, ERR_HANDSHAKE_TIMEOUT)
    }
    await within(2000, 'the WebSocket is still open', closed)
  }
})

// ---------------------------------------------------------------------------
// ML-KEM-1024, and WebSockets against 1.4.0 from npm
// ---------------------------------------------------------------------------

// The length of every message an end receives, as it arrives off the wire.
function heard(ws) {
  const lengths = []
  ws.on('message', (data) => lengths.push(data.length))
  return lengths
}

// One message each way over two connected channels, the responder first.
async function exchange(client, server, what) {
  server.send(Buffer.from('from the responder'))
  const down = await within(3000, `${what}: nothing reached the initiator`, nextMessage(client))
  assert.equal(down.toString(), 'from the responder', what)
  client.send(Buffer.from('from the initiator'))
  const up = await within(3000, `${what}: nothing reached the responder`, nextMessage(server))
  assert.equal(up.toString(), 'from the initiator', what)
}

const IDENTITIES = [
  ['no identities', {}, {}],
  ['ML-DSA-87 identities', { identity: initId87 }, { identity: respId87 }],
]

test('wrapWebSocket: an initiator on 1.4.0 reaches this responder on ML-KEM-768', async (t) => {
  for (const [label, i, r] of IDENTITIES) {
    const [c, s] = await wsPair(t)
    const atClient = heard(c)
    const atServer = heard(s)
    const [client, server] = await Promise.all([
      v140.wrapWebSocket(c, { role: 'initiator', handshakeTimeoutMs: 3000, ...i }),
      wrapWebSocket(s, { role: 'responder', handshakeTimeoutMs: 3000, ...r }),
    ])
    assert.equal(atServer[0], 1218, `${label}: the ClientHello`)
    assert.equal(atClient[0], 1122, `${label}: the ServerHello`)
    await exchange(client, server, label)
  }
})

test('wrapWebSocket: this initiator given kem: ml-kem-768 reaches a 1.4.0 responder', async (t) => {
  for (const kem of [{ kem: 'ml-kem-768' }]) {
    for (const [label, i, r] of IDENTITIES) {
      const what = `${kem.kem ?? 'default'}, ${label}`
      const [c, s] = await wsPair(t)
      const atServer = heard(s)
      const [client, server] = await Promise.all([
        wrapWebSocket(c, { role: 'initiator', handshakeTimeoutMs: 3000, ...kem, ...i }),
        v140.wrapWebSocket(s, { role: 'responder', handshakeTimeoutMs: 3000, ...r }),
      ])
      assert.equal(atServer[0], 1218, `${what}: the ClientHello`)
      await exchange(client, server, what)
    }
  }
})

test('wrapWebSocket: this initiator on ML-KEM-1024, by default or by name, meets a 1.4.0 or 1.2.4 responder: refused, nothing answered, both ends closed, and the initiator says why', async (t) => {
  for (const [kem, old, version] of [[{}, v140, '1.4.0'], [{ kem: 'ml-kem-1024' }, v140, '1.4.0'], [{}, v124, '1.2.4']]) {
    const what = `${kem.kem ?? 'default'}, responder ${version}`
    const [c, s] = await wsPair(t)
    const atClient = heard(c)
    const atServer = heard(s)
    const closed = Promise.all([new Promise((res) => c.once('close', res)), new Promise((res) => s.once('close', res))])
    const started = Date.now()
    const [client, server] = await Promise.all([
      outcome(wrapWebSocket(c, { role: 'initiator', handshakeTimeoutMs: 3000, ...kem })),
      outcome(old.wrapWebSocket(s, { role: 'responder', handshakeTimeoutMs: 3000 })),
    ])
    const elapsed = Date.now() - started
    // The whole hello arrives as one message, so its length is refused first.
    assert.equal(server.error?.message, 'ClientHello: expected 1218 bytes, got 1602', what)
    // The initiator learns of it from the close, at once, not at its deadline,
    // and says what the close most likely means, keeping the close as cause.
    assert.ok(client.error instanceof KxcoPqTlsError, `${what}: the initiator does not complete`)
    assert.equal(client.error.code, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024, what)
    assert.equal(client.error.message, 'the responder closed after an ML-KEM-1024 hello; a responder on ' +
      "kxco-pq-tls 1.4 or earlier cannot read it: upgrade it, or pass kem: 'ml-kem-768'", what)
    assert.equal(client.error.cause?.message, 'WebSocket closed during handshake', what)
    assert.ok(elapsed < 2000, `${what}: the initiator waited ${elapsed}ms`)
    await within(2000, `${what}: the WebSocket is still open`, closed)
    assert.deepEqual(atServer, [1602], `${what}: the responder received the one hello and nothing else`)
    assert.deepEqual(atClient, [], `${what}: the responder answered nothing`)
    assert.equal(c.readyState, 3, what)
    assert.equal(s.readyState, 3, what)
  }
})

test('wrapWebSocket: two ends on this version agree ML-KEM-1024, by default or by name, 1602-byte hellos both ways', async (t) => {
  const cases = [
    ['default, no identities', {}, {}],
    ['by name, no identities', { kem: 'ml-kem-1024' }, {}],
    ['default, ML-DSA-87 identities', { identity: initId87 }, { identity: respId87 }],
    ['by name, ML-DSA-87 identities', { kem: 'ml-kem-1024', identity: initId87 }, { identity: respId87 }],
  ]
  for (const [label, i, r] of cases) {
    const [c, s] = await wsPair(t)
    const atClient = heard(c)
    const atServer = heard(s)
    const [client, server] = await Promise.all([
      wrapWebSocket(c, { role: 'initiator', handshakeTimeoutMs: 3000, ...i }),
      wrapWebSocket(s, { role: 'responder', handshakeTimeoutMs: 3000, ...r }),
    ])
    assert.equal(atServer[0], 1602, `${label}: the ClientHello`)
    assert.equal(atClient[0], 1602, `${label}: the ServerHello`)
    if (i.identity) {
      assert.ok(sameKey(client.peerPublicKey, r.identity.publicKey), label)
      assert.ok(sameKey(server.peerPublicKey, i.identity.publicKey), label)
    }
    await exchange(client, server, label)
  }
})

test('wrapWebSocket: with mutual authentication, the ML-KEM-1024 flag flipped in flight fails the Finished check', async (t) => {
  const [c, s] = await wsPair(t)
  // Flip bit 3 of the first message the responder puts on the wire, its ServerHello.
  const send = s.send.bind(s)
  let sent = 0
  s.send = (data, cb) => {
    const out = Buffer.from(data)
    if (sent++ === 0) out[1] ^= 0x08
    return send(out, cb)
  }
  const [client, server] = await Promise.all([
    outcome(wrapWebSocket(c, { role: 'initiator', identity: initId87, kem: 'ml-kem-1024', handshakeTimeoutMs: 3000 })),
    outcome(wrapWebSocket(s, { role: 'responder', identity: respId87, handshakeTimeoutMs: 3000 })),
  ])
  assert.match(client.error?.message ?? '', /initiator: peer identity verification failed/)
  assert.match(server.error?.message ?? '', /responder: peer identity verification failed/)
})

test('wrapWebSocket: a 1218-byte hello that declares ML-KEM-1024 is refused at once, not waited on', async (t) => {
  // Each WebSocket message is a whole hello, so 1218 bytes with bit 3 set is
  // malformed: no more of it is coming. Through the handshake functions the
  // same hello is read as on a stream; see handshake.test.js.
  const [c, s] = await wsPair(t)
  const send = c.send.bind(c)
  let sent = 0
  c.send = (data, cb) => {
    const out = Buffer.from(data)
    if (sent++ === 0) out[1] |= 0x08
    return send(out, cb)
  }
  const started = Date.now()
  const [client, server] = await Promise.all([
    outcome(wrapWebSocket(c, { role: 'initiator', kem: 'ml-kem-768', handshakeTimeoutMs: 3000 })),
    outcome(wrapWebSocket(s, { role: 'responder', handshakeTimeoutMs: 3000 })),
  ])
  const elapsed = Date.now() - started
  assert.ok(server.error instanceof KxcoPqTlsError, 'the responder refuses')
  assert.equal(server.error.message, 'ClientHello: expected 1602 bytes, got 1218')
  assert.ok(elapsed < 1000, `the responder took ${elapsed}ms`)
  // The ML-KEM-768 initiator sees the close as the transport reports it.
  assert.equal(client.error?.message, 'WebSocket closed during handshake')
})

test('wrapWebSocket: this initiator on ML-KEM-1024 meets a 1.2.3 responder: refused by length, the connection left open, and the initiator explains the deadline', async (t) => {
  const deadline = 500
  const [c, s] = await wsPair(t)
  const atClient = heard(c)
  let firstClose = null
  const noteClose = () => { firstClose ??= Date.now() }
  c.once('close', noteClose)
  s.once('close', noteClose)
  const started = Date.now()
  const [client, server] = await Promise.all([
    outcome(wrapWebSocket(c, { role: 'initiator', handshakeTimeoutMs: deadline })),
    v123.wrapWebSocket(s, { role: 'responder', handshakeTimeoutMs: 3000 }).then(
      () => ({}),
      (error) => ({ error, after: Date.now() - started, open: [c.readyState, s.readyState] })),
  ])
  const elapsed = Date.now() - started
  // 1.2.3 refuses the 1602-byte hello by its length at once, answers nothing,
  // and does not close the WebSocket.
  assert.equal(server.error?.message, 'ClientHello: expected 1218 bytes, got 1602')
  assert.ok(server.after < deadline, `1.2.3 refused after ${server.after}ms`)
  assert.deepEqual(server.open, [1, 1], 'both ends still open when 1.2.3 refused')
  assert.deepEqual(atClient, [], 'the responder answered nothing')
  // So the initiator hears nothing until its deadline, then explains it, with
  // the timeout as cause.
  assert.ok(client.error instanceof KxcoPqTlsError, 'the initiator does not complete')
  assert.equal(client.error.code, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024)
  assert.equal(client.error.message, 'no valid ML-KEM-1024 ServerHello before the deadline; likely cause: ' +
    'a responder on kxco-pq-tls 1.2.4 or earlier ignores the ML-KEM-1024 flag, and one on 1.3 or 1.4 ' +
    "refuses it: upgrade the responder, or pass kem: 'ml-kem-768'")
  assert.equal(client.error.cause?.code, ERR_HANDSHAKE_TIMEOUT)
  assert.ok(elapsed >= deadline && elapsed < deadline + 1500, `the initiator failed after ${elapsed}ms`)
  // The connection stayed open until then: the first close is the initiator's own.
  await within(2000, 'the WebSocket is still open', new Promise((res) => (c.readyState === 3 ? res() : c.once('close', res))))
  assert.ok(firstClose - started >= deadline, `the connection closed after ${firstClose - started}ms`)
})
