// Property-based tests with fast-check.
//
// stream.test.js checks a handful of fixed messages over a real socket. These
// ask the general question: once the handshake is done, does a channel carry
// ANY sequence of messages, of any content, intact and in order in both
// directions at once, and refuse a record that has been changed, replayed,
// dropped or reordered on the way? fast-check generates the messages and,
// when a property breaks, shrinks the failing case to the smallest one that
// still breaks it, so a failure arrives as a minimal reproduction rather than
// a random blob.
//
// Both ends run in this process over an in-memory duplex pair, so nothing here
// opens a socket or touches the network. Every channel is the default one,
// with no identity keys on either side. Runs on whichever kxco-post-quantum
// backend is live.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Duplex } from 'node:stream'
import fc from 'fast-check'
import { wrapStream, KxcoPqTlsError } from '../src/index.js'

// Every case runs a full ML-KEM-768 and X25519 handshake, so a modest run
// count keeps the suite fast while covering a spread of lengths and orders.
const RUNS = { numRuns: 30 }

// Two connected in-memory streams. Whatever `a` writes arrives at `b` and the
// reverse, one chunk per write. With `link.hold` set, what `a` writes is kept
// back in `link.held` instead, so a test can edit the records before they
// arrive.
function memoryPair() {
  const link = { hold: false, held: [] }
  let a = null
  let b = null
  a = new Duplex({
    read() {},
    write(chunk, _enc, cb) {
      if (link.hold) link.held.push(Buffer.from(chunk))
      else b.push(chunk)
      cb()
    },
    final(cb) {
      if (!link.hold) b.push(null)
      cb()
    },
  })
  b = new Duplex({
    read() {},
    write(chunk, _enc, cb) { a.push(chunk); cb() },
    final(cb) { a.push(null); cb() },
  })
  return { a, b, link }
}

async function connect() {
  const pair = memoryPair()
  const [client, server] = await Promise.all([
    wrapStream(pair.a, { role: 'initiator' }),
    wrapStream(pair.b, { role: 'responder' }),
  ])
  return { ...pair, client, server }
}

// Everything a stream delivers, and how it stopped: a clean end or an error.
// After an error it waits one more turn of the event loop before reporting,
// so anything released late still counts.
function drain(stream) {
  const chunks = []
  stream.on('data', (d) => chunks.push(Buffer.from(d)))
  return new Promise((resolve) => {
    stream.once('end', () => resolve({ data: Buffer.concat(chunks), error: null }))
    stream.once('error', (error) => setImmediate(() => resolve({ data: Buffer.concat(chunks), error })))
  })
}

// Split the wire bytes after the handshake into records: a 4-byte big-endian
// length, then that many bytes of ciphertext and GCM tag.
function records(wire) {
  const out = []
  for (let at = 0; at < wire.length;) {
    const n = wire.readUInt32BE(at)
    out.push(Buffer.from(wire.subarray(at, at + 4 + n)))
    at += 4 + n
  }
  return out
}

// Send `messages` from client to server with the records held back, let
// `edit` change the list of records, deliver what it returns, and report what
// the server released and how it stopped.
async function sendEdited(messages, edit) {
  const { b, link, client, server } = await connect()
  link.hold = true
  const received = drain(server)
  const finished = new Promise((resolve) => client.once('finish', resolve))
  for (const m of messages) client.write(m)
  client.end()
  await finished
  const sent = records(Buffer.concat(link.held))
  assert.equal(sent.length, messages.length)
  for (const r of edit(sent)) b.push(r)
  b.push(null)
  return received
}

// `size: 'max'` spreads lengths over the whole range; fast-check's default
// keeps them near ten.
const messages = (min) => fc.array(fc.uint8Array({ minLength: 1, maxLength: 256, size: 'max' }), { minLength: min, maxLength: 12, size: 'max' })
const joined = (list) => Buffer.concat(list.map((m) => Buffer.from(m)))

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('stream: many messages keep their order, in both directions at once', async () => {
  const burst = fc.array(fc.uint8Array({ maxLength: 512, size: 'max' }), { maxLength: 40, size: 'max' })
  await fc.assert(fc.asyncProperty(burst, burst, async (up, down) => {
    const { client, server } = await connect()
    const atServer = drain(server)
    const atClient = drain(client)
    for (let i = 0; i < Math.max(up.length, down.length); i++) {
      if (i < up.length) client.write(Buffer.from(up[i]))
      if (i < down.length) server.write(Buffer.from(down[i]))
    }
    client.end()
    server.end()
    const [s, c] = await Promise.all([atServer, atClient])
    return s.error === null && c.error === null && s.data.equals(joined(up)) && c.data.equals(joined(down))
  }), RUNS)
})

test('stream: a record changed in flight is refused, and nothing from it onward is released', async () => {
  await fc.assert(fc.asyncProperty(messages(1), fc.nat(), fc.nat(), fc.integer({ min: 1, max: 255 }), async (msgs, which, at, mask) => {
    const i = which % msgs.length
    const { data, error } = await sendEdited(msgs, (recs) => {
      // Any byte of the ciphertext or tag; the 4-byte length prefix is left alone.
      const r = recs[i]
      r[4 + (at % (r.length - 4))] ^= mask
      return recs
    })
    return error instanceof KxcoPqTlsError && data.equals(joined(msgs.slice(0, i)))
  }), RUNS)
})

test('stream: a record replayed, dropped or reordered is refused, and nothing from it onward is released', async () => {
  const change = fc.constantFrom('replay', 'drop', 'swap')
  await fc.assert(fc.asyncProperty(messages(2), fc.nat(), change, async (msgs, which, how) => {
    // Always an earlier record than the last, so a later one exists to arrive
    // out of sequence.
    const i = which % (msgs.length - 1)
    const { data, error } = await sendEdited(msgs, (recs) => {
      if (how === 'replay') return [...recs.slice(0, i + 1), recs[i], ...recs.slice(i + 1)]
      if (how === 'drop') return [...recs.slice(0, i), ...recs.slice(i + 1)]
      return [...recs.slice(0, i), recs[i + 1], recs[i], ...recs.slice(i + 2)]
    })
    const intact = how === 'replay' ? i + 1 : i
    return error instanceof KxcoPqTlsError && data.equals(joined(msgs.slice(0, intact)))
  }), RUNS)
})

test('stream: a message of exactly 16 KiB, the stream high-water mark, arrives and the stream then ends', async () => {
  const { client, server } = await connect()
  let got = 0
  server.on('data', (d) => { got += d.length })
  const received = drain(server)
  client.end(Buffer.alloc(16384, 0x61))
  let timer
  const stalled = new Promise((resolve) => { timer = setTimeout(() => resolve(null), 3000) })
  const result = await Promise.race([received, stalled])
  clearTimeout(timer)
  assert.ok(result, `stalled after ${got} of 16384 bytes with no end`)
  assert.equal(result.error, null)
  assert.equal(result.data.length, 16384)
})

test('stream: a message of any length sent after the handshake arrives intact, and the stream then ends', async () => {
  // Up to eight times the stream's 16 KiB high-water mark.
  const message = fc.uint8Array({ maxLength: 128 * 1024, size: 'max' })
  await fc.assert(fc.asyncProperty(message, async (m) => {
    const { client, server } = await connect()
    const received = drain(server)
    client.end(Buffer.from(m))
    const { data, error } = await received
    return error === null && data.equals(Buffer.from(m))
  }), RUNS)
})
