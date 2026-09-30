/**
 * End-to-end tests using real net.Socket pairs.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import { Writable } from 'node:stream'
import { mlDsa } from 'kxco-post-quantum'
import { wrapStream } from '../src/stream.js'
import { KxcoPqTlsError } from '../src/errors.js'

const initId = mlDsa.ml_dsa65.keygen()
const respId = mlDsa.ml_dsa65.keygen()
const relayId = mlDsa.ml_dsa65.keygen()

const sameKey = (reported, publicKey) =>
  reported !== undefined && Buffer.from(reported).equals(Buffer.from(publicKey))

const outcome = (p) => p.then((value) => ({ value }), (error) => ({ error }))

// Resolves as `promise` does, or fails after `ms` with what `progress()` says,
// so a stalled stream reports how far it got instead of holding the run open.
async function within(ms, progress, promise) {
  let timer
  const late = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`stalled: ${progress()}`)), ms)
  })
  try {
    return await Promise.race([promise, late])
  } finally {
    clearTimeout(timer)
  }
}

// Creates a connected socket pair via a local TCP server.
function socketPair() {
  return new Promise((resolve, reject) => {
    let clientSock
    const server = net.createServer((serverSock) => {
      server.close()
      resolve([clientSock, serverSock])
    })
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      clientSock = net.connect(port, '127.0.0.1')
      clientSock.once('error', reject)
    })
    server.once('error', reject)
  })
}

// Reads all data from a stream until it ends.
function readAll(stream) {
  return new Promise((resolve, reject) => {
    const chunks = []
    stream.on('data',  (c) => chunks.push(c))
    stream.on('end',   ()  => resolve(Buffer.concat(chunks)))
    stream.on('error', reject)
  })
}

test('wrapStream: single message roundtrip', async () => {
  const [c, s] = await socketPair()
  const [client, server] = await Promise.all([
    wrapStream(c, { role: 'initiator' }),
    wrapStream(s, { role: 'responder' }),
  ])

  client.write('hello from client')
  const chunk = await new Promise((res) => server.once('data', res))
  assert.equal(chunk.toString(), 'hello from client')

  client.end()
  server.end()
})

test('wrapStream: server to client', async () => {
  const [c, s] = await socketPair()
  const [client, server] = await Promise.all([
    wrapStream(c, { role: 'initiator' }),
    wrapStream(s, { role: 'responder' }),
  ])

  server.write(Buffer.from('hello from server'))
  const chunk = await new Promise((res) => client.once('data', res))
  assert.equal(chunk.toString(), 'hello from server')

  client.end()
  server.end()
})

test('wrapStream: multiple sequential messages', async () => {
  const [c, s] = await socketPair()
  const [client, server] = await Promise.all([
    wrapStream(c, { role: 'initiator' }),
    wrapStream(s, { role: 'responder' }),
  ])

  const messages = ['alpha', 'beta', 'gamma', 'delta']
  const received = []

  const allReceived = new Promise((resolve) => {
    server.on('data', (d) => {
      received.push(d.toString())
      if (received.length === messages.length) resolve()
    })
  })

  for (const m of messages) client.write(m)
  await allReceived

  assert.deepEqual(received, messages)
  client.end()
  server.end()
})

test('wrapStream: large payload (512KB)', async () => {
  const [c, s] = await socketPair()
  const [client, server] = await Promise.all([
    wrapStream(c, { role: 'initiator' }),
    wrapStream(s, { role: 'responder' }),
  ])

  const payload = Buffer.alloc(512 * 1024, 0x42)
  client.end(payload)

  const received = await readAll(server)
  assert.equal(received.length, payload.length)
  assert.deepEqual(received, payload)

  server.end()
})

test('wrapStream: bidirectional simultaneous', async () => {
  const [c, s] = await socketPair()
  const [client, server] = await Promise.all([
    wrapStream(c, { role: 'initiator' }),
    wrapStream(s, { role: 'responder' }),
  ])

  client.write('ping')
  server.write('pong')

  const [fromServer, fromClient] = await Promise.all([
    new Promise((res) => client.once('data', res)),
    new Promise((res) => server.once('data', res)),
  ])

  assert.equal(fromServer.toString(), 'pong')
  assert.equal(fromClient.toString(), 'ping')

  client.end()
  server.end()
})

test('wrapStream: tampered frame closes stream with error', async () => {
  const [c, s] = await socketPair()
  const [client, server] = await Promise.all([
    wrapStream(c, { role: 'initiator' }),
    wrapStream(s, { role: 'responder' }),
  ])

  // Write a fake frame via the client's underlying socket — server receives it and fails auth.
  const fake = Buffer.alloc(20, 0xff)
  fake.writeUInt32BE(16, 0)  // length=16, then 16 bytes of garbage (no valid GCM tag)

  const err = await new Promise((res) => {
    server.once('error', res)
    client._socket.write(fake)
  })

  assert.ok(err instanceof KxcoPqTlsError || err.message.includes('authentication'))
  c.destroy()
  s.destroy()
})

test('wrapStream: missing role throws', async () => {
  const [c] = await socketPair()
  await assert.rejects(wrapStream(c, {}), /role is required/)
  c.destroy()
})

// A socket pair destroyed when the test ends, whatever its outcome, so a
// handshake that fails part way cannot hold the run open.
async function pairFor(t) {
  const [c, s] = await socketPair()
  t.after(() => { c.destroy(); s.destroy() })
  return [c, s]
}

// ---------------------------------------------------------------------------
// Frames that arrive together
// ---------------------------------------------------------------------------

test('wrapStream: a record the responder sends straight after the handshake arrives', async (t) => {
  // The record can reach the initiator in the same TCP chunk as the ServerHello.
  const [c, s] = await pairFor(t)
  const [client] = await Promise.all([
    wrapStream(c, { role: 'initiator', handshakeTimeoutMs: 3000 }),
    wrapStream(s, { role: 'responder', handshakeTimeoutMs: 3000 })
      .then((server) => server.write('first word from server')),
  ])
  const chunk = await within(3000, () => 'no record reached the client',
    new Promise((res) => client.once('data', res)))
  assert.equal(chunk.toString(), 'first word from server')
})

test('wrapStream: mutual authentication over TCP, each side reporting the key the other proved', async (t) => {
  // The responder sends its ServerHello and Finished back to back, then speaks first.
  const [c, s] = await pairFor(t)
  const [client, server] = await Promise.all([
    wrapStream(c, { role: 'initiator', identity: initId, handshakeTimeoutMs: 3000 }),
    wrapStream(s, { role: 'responder', identity: respId, handshakeTimeoutMs: 3000 })
      .then((server) => { server.write('greeting'); return server }),
  ])
  assert.ok(sameKey(client.peerPublicKey, respId.publicKey), 'the client reports the server key')
  assert.ok(sameKey(server.peerPublicKey, initId.publicKey), 'the server reports the client key')

  const greeting = await within(3000, () => 'no greeting', new Promise((res) => client.once('data', res)))
  assert.equal(greeting.toString(), 'greeting')
  client.write('reply')
  const reply = await within(3000, () => 'no reply', new Promise((res) => server.once('data', res)))
  assert.equal(reply.toString(), 'reply')
})

// ---------------------------------------------------------------------------
// Peer identity
// ---------------------------------------------------------------------------

test('wrapStream: a relay holding its own identity shows in peerPublicKey, and is refused once the peer key is pinned', async (t) => {
  // Real TCP on both legs. The relay terminates each connection with its own
  // key and copies the plaintext across.
  const relayed = async (pinned) => {
    const [a, relayFromA] = await pairFor(t)
    const [relayToB, b] = await pairFor(t)
    return Promise.all([
      outcome(wrapStream(a, {
        role: 'initiator', identity: initId, handshakeTimeoutMs: 3000,
        ...(pinned && { peerPublicKey: respId.publicKey }),
      })),
      outcome(wrapStream(relayFromA, { role: 'responder', identity: relayId, handshakeTimeoutMs: 3000 })),
      outcome(wrapStream(relayToB, { role: 'initiator', identity: relayId, handshakeTimeoutMs: 3000 })),
      outcome(wrapStream(b, {
        role: 'responder', identity: respId, handshakeTimeoutMs: 3000,
        ...(pinned && { peerPublicKey: initId.publicKey }),
      })),
    ])
  }

  const open = await relayed(false)
  for (const side of open) assert.ifError(side.error)
  const [client, relayA, relayB, server] = open.map((side) => side.value)
  assert.ok(sameKey(client.peerPublicKey, relayId.publicKey), 'the client sees the relay key')
  assert.ok(sameKey(server.peerPublicKey, relayId.publicKey), 'the server sees the relay key')
  relayA.pipe(relayB)
  relayB.pipe(relayA)
  client.write('through the relay')
  const chunk = await within(3000, () => 'nothing crossed the relay', new Promise((res) => server.once('data', res)))
  assert.equal(chunk.toString(), 'through the relay')

  const [pc, , , ps] = await relayed(true)
  assert.ok(pc.error instanceof KxcoPqTlsError, 'the pinned client refuses the relay')
  assert.match(pc.error.message, /pinned peerPublicKey/)
  assert.ok(ps.error instanceof KxcoPqTlsError, 'the pinned server refuses the relay')
  assert.match(ps.error.message, /pinned peerPublicKey/)
})

test('wrapStream: a responder holding an identity refuses an initiator without one', async (t) => {
  const [c, s] = await pairFor(t)
  const [client, server] = await Promise.all([
    outcome(wrapStream(c, { role: 'initiator', handshakeTimeoutMs: 3000 })),
    // A server that closes the connection when its handshake fails.
    outcome(wrapStream(s, { role: 'responder', identity: respId, handshakeTimeoutMs: 3000 })
      .catch((err) => { s.destroy(); throw err })),
  ])
  assert.ok(server.error instanceof KxcoPqTlsError, 'the server refuses')
  assert.match(server.error.message, /did not request mutual authentication/)
  assert.ok(client.error instanceof KxcoPqTlsError, 'the client does not complete')
})

// ---------------------------------------------------------------------------
// Back-pressure
// ---------------------------------------------------------------------------

test('wrapStream: for await reads every byte of two 32 KiB writes', async (t) => {
  const [c, s] = await pairFor(t)
  const [client, server] = await Promise.all([
    wrapStream(c, { role: 'initiator' }),
    wrapStream(s, { role: 'responder' }),
  ])
  client.write(Buffer.alloc(32768, 1))
  client.end(Buffer.alloc(32768, 2))
  let got = 0
  await within(3000, () => `for await stopped at ${got} of 65536 bytes`, (async () => {
    for await (const d of server) got += d.length
  })())
  assert.equal(got, 65536)
})

test('wrapStream: pipe into a slow writable delivers all of 1 MiB', async (t) => {
  const [c, s] = await pairFor(t)
  const [client, server] = await Promise.all([
    wrapStream(c, { role: 'initiator' }),
    wrapStream(s, { role: 'responder' }),
  ])
  let got = 0
  const slow = new Writable({
    write(chunk, _enc, cb) { got += chunk.length; setTimeout(cb, 1) },
  })
  const finished = new Promise((res, rej) => { slow.once('finish', res); slow.once('error', rej) })
  server.pipe(slow)
  for (let i = 0; i < 16; i++) client.write(Buffer.alloc(65536, i))
  client.end()
  await within(5000, () => `the pipe stopped at ${got} of 1048576 bytes`, finished)
  assert.equal(got, 1048576)
})
