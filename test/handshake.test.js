/**
 * Tests for the handshake protocol using in-memory message queues —
 * no real sockets needed. Both sides run concurrently via Promise.all.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { initiatorHandshake, responderHandshake } from '../src/handshake.js'
import { ERR_HANDSHAKE_TIMEOUT } from '../src/errors.js'
import { mlDsa } from 'kxco-post-quantum'

// Generate once and reuse across auth tests — keygen is the expensive step
const initId = mlDsa.ml_dsa65.keygen()
const respId = mlDsa.ml_dsa65.keygen()

// Pairs two async queues so initiator and responder can talk in memory.
function makeInMemoryChannel() {
  const q1 = []  // initiator → responder
  const q2 = []  // responder → initiator
  const r1 = []  // resolve callbacks for responder waiting on q1
  const r2 = []  // resolve callbacks for initiator waiting on q2

  const push = (queue, waiters, msg) => {
    if (waiters.length) waiters.shift()(msg)
    else queue.push(msg)
  }
  const pop = (queue, waiters) => {
    if (queue.length) return Promise.resolve(queue.shift())
    return new Promise(res => waiters.push(res))
  }

  return {
    initiatorSend: (data) => { push(q1, r1, data); return Promise.resolve() },
    initiatorRecv: ()     => pop(q2, r2),
    responderSend: (data) => { push(q2, r2, data); return Promise.resolve() },
    responderRecv: ()     => pop(q1, r1),
  }
}

test('basic handshake: both sides derive equal session keys', async () => {
  const ch = makeInMemoryChannel()
  const [init, resp] = await Promise.all([
    initiatorHandshake(ch.initiatorSend, ch.initiatorRecv),
    responderHandshake(ch.responderSend, ch.responderRecv),
  ])

  // initiator txKey must equal responder rxKey (C2S direction)
  assert.deepEqual(init.txKey, resp.rxKey)
  // responder txKey must equal initiator rxKey (S2C direction)
  assert.deepEqual(resp.txKey, init.rxKey)
})

test('handshake keys are different per direction', async () => {
  const ch = makeInMemoryChannel()
  const [init] = await Promise.all([
    initiatorHandshake(ch.initiatorSend, ch.initiatorRecv),
    responderHandshake(ch.responderSend, ch.responderRecv),
  ])
  assert.notDeepEqual(init.txKey, init.rxKey)
})

test('two separate handshakes produce different keys', async () => {
  const ch1 = makeInMemoryChannel()
  const ch2 = makeInMemoryChannel()

  const [[i1], [i2]] = await Promise.all([
    Promise.all([
      initiatorHandshake(ch1.initiatorSend, ch1.initiatorRecv),
      responderHandshake(ch1.responderSend, ch1.responderRecv),
    ]),
    Promise.all([
      initiatorHandshake(ch2.initiatorSend, ch2.initiatorRecv),
      responderHandshake(ch2.responderSend, ch2.responderRecv),
    ]),
  ])
  assert.notDeepEqual(i1.txKey, i2.txKey)
})

test('mutual auth handshake succeeds with valid identity keys', async () => {
  const initId = mlDsa.ml_dsa65.keygen()
  const respId = mlDsa.ml_dsa65.keygen()
  const ch = makeInMemoryChannel()

  const [init, resp] = await Promise.all([
    initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: initId }),
    responderHandshake(ch.responderSend, ch.responderRecv, { identity: respId }),
  ])

  assert.deepEqual(init.txKey, resp.rxKey)
  assert.deepEqual(resp.txKey, init.rxKey)
})

test('mutual auth: tampered Finished signature is rejected', async () => {
  const initId = mlDsa.ml_dsa65.keygen()
  const respId = mlDsa.ml_dsa65.keygen()
  const ch = makeInMemoryChannel()

  // Intercept and corrupt the initiator's Finished message
  let firstMsg = true
  const corruptSend = async (data) => {
    if (firstMsg) {
      firstMsg = false
      // Skip first two handshake messages (ClientHello, Finished-encrypted)
      // The Finished is sent after the handshake messages; corrupt last byte
      const corrupted = Buffer.from(data)
      corrupted[corrupted.length - 1] ^= 0xff
      return ch.initiatorSend(corrupted)
    }
    return ch.initiatorSend(data)
  }

  await assert.rejects(
    Promise.all([
      initiatorHandshake(corruptSend, ch.initiatorRecv, { identity: initId }),
      responderHandshake(ch.responderSend, ch.responderRecv, { identity: respId }),
    ]),
    /authentication failed|identity verification failed/
  )
})

// ---------------------------------------------------------------------------
// Handshake deadline
// ---------------------------------------------------------------------------

test('mismatched auth config fails with a timeout instead of hanging', async () => {
  // The exact stall this deadline exists for. The initiator holds an identity
  // so it sets the auth flag and waits for a Finished frame. The responder has
  // no identity, so it completes without ever sending one. Before the deadline
  // the initiator waited here for as long as the caller let it.
  const ch = makeInMemoryChannel()

  const responder = responderHandshake(ch.responderSend, ch.responderRecv, {})
  const initiator = initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, {
    identity: initId,
    handshakeTimeoutMs: 200,
  })

  // The responder is not the one that stalls: it finishes normally.
  await responder

  const err = await initiator.then(
    () => { throw new Error('expected the initiator to time out') },
    (e) => e,
  )
  assert.equal(err.name, 'KxcoPqTlsError')
  assert.equal(err.code, ERR_HANDSHAKE_TIMEOUT)
  assert.match(err.message, /within 200ms/)
})

test('a silent peer times out rather than waiting forever', async () => {
  const never = () => new Promise(() => {})
  const err = await initiatorHandshake(async () => {}, never, { handshakeTimeoutMs: 100 })
    .then(() => { throw new Error('expected a timeout') }, (e) => e)

  assert.equal(err.code, ERR_HANDSHAKE_TIMEOUT)
})

test('the deadline does not fire on a handshake that completes', async () => {
  const ch = makeInMemoryChannel()
  const [init, resp] = await Promise.all([
    initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, {
      identity: initId, handshakeTimeoutMs: 10_000,
    }),
    responderHandshake(ch.responderSend, ch.responderRecv, {
      identity: respId, handshakeTimeoutMs: 10_000,
    }),
  ])
  assert.deepEqual(init.txKey, resp.rxKey)
  assert.deepEqual(init.rxKey, resp.txKey)
})

test('handshakeTimeoutMs: 0 restores the unbounded wait', async () => {
  const never = () => new Promise(() => {})
  const settled = await Promise.race([
    initiatorHandshake(async () => {}, never, { handshakeTimeoutMs: 0 })
      .then(() => 'resolved', () => 'rejected'),
    new Promise(res => setTimeout(() => res('still waiting'), 300)),
  ])
  assert.equal(settled, 'still waiting')
})
