/**
 * Tests for the handshake protocol using in-memory message queues —
 * no real sockets needed. Both sides run concurrently via Promise.all.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { initiatorHandshake, responderHandshake } from '../src/handshake.js'
import { mlDsa } from 'kxco-post-quantum'

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
