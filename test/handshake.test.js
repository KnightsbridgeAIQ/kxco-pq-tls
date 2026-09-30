/**
 * Tests for the handshake protocol using in-memory message queues —
 * no real sockets needed. Both sides run concurrently via Promise.all.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { initiatorHandshake, responderHandshake } from '../src/handshake.js'
import { KxcoPqTlsError, ERR_HANDSHAKE_TIMEOUT } from '../src/errors.js'
import { sealFrame, openFrame } from '../src/primitives.js'
import { mlDsa } from 'kxco-post-quantum'

// Generate once and reuse across auth tests — keygen is the expensive step
const initId = mlDsa.ml_dsa65.keygen()
const respId = mlDsa.ml_dsa65.keygen()
const relayId = mlDsa.ml_dsa65.keygen()

// Whether a reported peer key is exactly the given public key.
const sameKey = (reported, publicKey) =>
  reported !== undefined && Buffer.from(reported).equals(Buffer.from(publicKey))

// Settle a handshake as its result or its error, for tests that expect one side to fail.
const outcome = (p) => p.then((value) => ({ value }), (error) => ({ error }))

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

// ---------------------------------------------------------------------------
// Peer identity
// ---------------------------------------------------------------------------

test('mutual auth: each side reports the key the other proved, and none without auth', async () => {
  const ch = makeInMemoryChannel()
  const [init, resp] = await Promise.all([
    initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: initId }),
    responderHandshake(ch.responderSend, ch.responderRecv, { identity: respId }),
  ])
  assert.ok(sameKey(init.peerPublicKey, respId.publicKey), 'initiator reports the responder key')
  assert.ok(sameKey(resp.peerPublicKey, initId.publicKey), 'responder reports the initiator key')

  const plain = makeInMemoryChannel()
  const [i2, r2] = await Promise.all([
    initiatorHandshake(plain.initiatorSend, plain.initiatorRecv),
    responderHandshake(plain.responderSend, plain.responderRecv),
  ])
  assert.equal(i2.peerPublicKey, undefined)
  assert.equal(r2.peerPublicKey, undefined)
})

test('a responder holding an identity refuses an initiator that does not request mutual auth', async () => {
  const ch = makeInMemoryChannel()
  const [init, resp] = await Promise.all([
    outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { handshakeTimeoutMs: 300 })),
    outcome(responderHandshake(ch.responderSend, ch.responderRecv, { identity: respId })),
  ])
  assert.ok(resp.error instanceof KxcoPqTlsError, 'the responder refuses')
  assert.match(resp.error.message, /did not request mutual authentication/)
  // It refuses before answering, so the initiator never completes either.
  assert.ok(init.error instanceof KxcoPqTlsError, 'the initiator does not complete')
})

test('a pinned peer key that matches completes, on both sides', async () => {
  const ch = makeInMemoryChannel()
  const [init, resp] = await Promise.all([
    initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: initId, peerPublicKey: respId.publicKey }),
    responderHandshake(ch.responderSend, ch.responderRecv, { identity: respId, peerPublicKey: initId.publicKey }),
  ])
  assert.deepEqual(init.txKey, resp.rxKey)
  assert.ok(sameKey(init.peerPublicKey, respId.publicKey))
  assert.ok(sameKey(resp.peerPublicKey, initId.publicKey))
})

test('a pinned peer key that does not match fails the handshake, on either side', async () => {
  for (const pinOn of ['initiator', 'responder']) {
    const ch = makeInMemoryChannel()
    const [init, resp] = await Promise.all([
      outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, {
        identity: initId, handshakeTimeoutMs: 2000,
        ...(pinOn === 'initiator' && { peerPublicKey: relayId.publicKey }),
      })),
      outcome(responderHandshake(ch.responderSend, ch.responderRecv, {
        identity: respId, handshakeTimeoutMs: 2000,
        ...(pinOn === 'responder' && { peerPublicKey: relayId.publicKey }),
      })),
    ])
    const pinned = pinOn === 'initiator' ? init : resp
    assert.ok(pinned.error instanceof KxcoPqTlsError, `the ${pinOn} refuses`)
    assert.match(pinned.error.message, /pinned peerPublicKey/)
  }
})

test('a relay holding its own identity shows in peerPublicKey, and is refused once the peer key is pinned', async () => {
  // The relay runs a full handshake with each end, as the responder to one and
  // the initiator to the other, signing both with its own key.
  const relayed = async (pinned) => {
    const left  = makeInMemoryChannel()
    const right = makeInMemoryChannel()
    return Promise.all([
      outcome(initiatorHandshake(left.initiatorSend, left.initiatorRecv, {
        identity: initId, handshakeTimeoutMs: 2000, ...(pinned && { peerPublicKey: respId.publicKey }),
      })),
      outcome(responderHandshake(left.responderSend, left.responderRecv, { identity: relayId, handshakeTimeoutMs: 2000 })),
      outcome(initiatorHandshake(right.initiatorSend, right.initiatorRecv, { identity: relayId, handshakeTimeoutMs: 2000 })),
      outcome(responderHandshake(right.responderSend, right.responderRecv, {
        identity: respId, handshakeTimeoutMs: 2000, ...(pinned && { peerPublicKey: initId.publicKey }),
      })),
    ])
  }

  const [a, , , b] = await relayed(false)
  assert.ok(sameKey(a.value.peerPublicKey, relayId.publicKey), 'the initiator sees the relay key')
  assert.ok(sameKey(b.value.peerPublicKey, relayId.publicKey), 'the responder sees the relay key')

  const [pa, , , pb] = await relayed(true)
  assert.ok(pa.error instanceof KxcoPqTlsError, 'the pinned initiator refuses the relay')
  assert.ok(pb.error instanceof KxcoPqTlsError, 'the pinned responder refuses the relay')
})

test('a pinned peer key needs an identity on this side, and must be an ML-DSA-65 public key', async () => {
  const never = () => new Promise(() => {})
  await assert.rejects(
    initiatorHandshake(async () => {}, never, { peerPublicKey: respId.publicKey, handshakeTimeoutMs: 300 }),
    (err) => err instanceof KxcoPqTlsError && /needs an identity/.test(err.message),
  )
  await assert.rejects(
    responderHandshake(async () => {}, never, { peerPublicKey: initId.publicKey, handshakeTimeoutMs: 300 }),
    (err) => err instanceof KxcoPqTlsError && /needs an identity/.test(err.message),
  )
  await assert.rejects(
    initiatorHandshake(async () => {}, never, { identity: initId, peerPublicKey: Buffer.from('ab'), handshakeTimeoutMs: 300 }),
    (err) => err instanceof KxcoPqTlsError && /1952-byte/.test(err.message),
  )
})

// A responder with no identity that completes the key exchange, then sends the
// initiator's own Finished frame back, sealed in its own direction.
async function reflectingResponder(ch) {
  const keys = await responderHandshake(ch.responderSend, ch.responderRecv, {})
  const theirs = openFrame(keys.rxKey, 0, Buffer.from(await ch.responderRecv()))
  await ch.responderSend(Buffer.from(sealFrame(keys.txKey, 0, theirs)))
}

// An initiator that asks for mutual authentication, keeps its own Finished
// frame back, and sends the responder's Finished frame back to it instead.
async function reflectingInitiator(ch, identity) {
  let responderFinished
  let sent = 0
  const send = (data) => (++sent === 2 ? Promise.resolve() : ch.initiatorSend(data))
  const recv = async () => {
    const msg = await ch.initiatorRecv()
    responderFinished = msg
    return msg
  }
  const keys = await initiatorHandshake(send, recv, { identity })
  const theirs = openFrame(keys.rxKey, 0, Buffer.from(responderFinished))
  await ch.initiatorSend(Buffer.from(sealFrame(keys.txKey, 0, theirs)))
}

test('a Finished frame sent back to the side that signed it is refused, with a shared key too', async () => {
  const t = { handshakeTimeoutMs: 2000 }

  // To an initiator, from a responder that holds no key.
  let ch = makeInMemoryChannel()
  let [init] = await Promise.all([
    outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: initId, ...t })),
    outcome(reflectingResponder(ch)),
  ])
  assert.ok(init.error instanceof KxcoPqTlsError, 'the initiator refuses its own Finished frame')

  // Both ends share one identity and pin it: the peer's key is the same key,
  // so only the signature's role can tell a reflection apart.
  const shared = initId
  ch = makeInMemoryChannel()
  ;[init] = await Promise.all([
    outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: shared, peerPublicKey: shared.publicKey, ...t })),
    outcome(reflectingResponder(ch)),
  ])
  assert.ok(init.error instanceof KxcoPqTlsError, 'a pinned shared-key initiator refuses its own Finished frame')

  ch = makeInMemoryChannel()
  const [resp] = await Promise.all([
    outcome(responderHandshake(ch.responderSend, ch.responderRecv, { identity: shared, peerPublicKey: shared.publicKey, ...t })),
    outcome(reflectingInitiator(ch, relayId)),
  ])
  assert.ok(resp.error instanceof KxcoPqTlsError, 'a pinned shared-key responder refuses its own Finished frame')

  // A real shared-key pair still completes.
  ch = makeInMemoryChannel()
  const [i2, r2] = await Promise.all([
    initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: shared, peerPublicKey: shared.publicKey }),
    responderHandshake(ch.responderSend, ch.responderRecv, { identity: shared, peerPublicKey: shared.publicKey }),
  ])
  assert.deepEqual(i2.txKey, r2.rxKey)
  assert.ok(sameKey(i2.peerPublicKey, shared.publicKey))
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
