/**
 * End-to-end tests using real net.Socket pairs.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import { wrapStream } from '../src/stream.js'
import { KxcoPqTlsError } from '../src/errors.js'

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
