/**
 * Tests for the handshake protocol using in-memory message queues —
 * no real sockets needed. Both sides run concurrently via Promise.all.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { initiatorHandshake, responderHandshake } from '../src/handshake.js'
import { KxcoPqTlsError, ERR_HANDSHAKE_TIMEOUT, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024 } from '../src/errors.js'
import { sealFrame, openFrame } from '../src/primitives.js'
import { mlDsa, mlDsa87 } from 'kxco-post-quantum'
// The release on npm before ML-KEM-1024, unmodified.
import * as v140 from 'kxco-pq-tls-140'
// The last release before responders checked hello flags, unmodified.
import * as v124 from 'kxco-pq-tls-124'

// Generate once and reuse across auth tests — keygen is the expensive step
const initId = mlDsa.ml_dsa65.keygen()
const respId = mlDsa.ml_dsa65.keygen()
const relayId = mlDsa.ml_dsa65.keygen()
const initId87 = mlDsa87.ml_dsa87.keygen()
const respId87 = mlDsa87.ml_dsa87.keygen()
const relayId87 = mlDsa87.ml_dsa87.keygen()

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
  const err = await initiatorHandshake(async () => {}, never, { handshakeTimeoutMs: 100, kem: 'ml-kem-768' })
    .then(() => { throw new Error('expected a timeout') }, (e) => e)

  assert.equal(err.code, ERR_HANDSHAKE_TIMEOUT)

  // On ML-KEM-1024, the default, the same deadline names the likely cause
  // and keeps the timeout as its cause.
  const late = await initiatorHandshake(async () => {}, never, { handshakeTimeoutMs: 100 })
    .then(() => { throw new Error('expected a timeout') }, (e) => e)
  assert.equal(late.code, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024)
  assert.equal(late.cause?.code, ERR_HANDSHAKE_TIMEOUT)
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

test('a pinned peer key needs an identity on this side, and must be an ML-DSA-87 or ML-DSA-65 public key', async () => {
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

// ---------------------------------------------------------------------------
// Parameter sets: ML-DSA-87 and ML-DSA-65
// ---------------------------------------------------------------------------

// Every pairing of the two sets, initiator first.
const PAIRINGS = [
  ['ML-DSA-87', 'ML-DSA-87', initId87, respId87],
  ['ML-DSA-87', 'ML-DSA-65', initId87, respId],
  ['ML-DSA-65', 'ML-DSA-87', initId, respId87],
  ['ML-DSA-65', 'ML-DSA-65', initId, respId],
]

// An in-memory channel that keeps a copy of every message each side sends,
// and passes each one through `tamper` on its way to the other side.
function recordingChannel(tamper = (_role, _index, data) => data) {
  const ch = makeInMemoryChannel()
  const sent = { initiator: [], responder: [] }
  const wrap = (role, send) => (data) => {
    const index = sent[role].push(Buffer.from(data)) - 1
    return send(tamper(role, index, Buffer.from(data)))
  }
  return {
    sent,
    initiatorSend: wrap('initiator', ch.initiatorSend), initiatorRecv: ch.initiatorRecv,
    responderSend: wrap('responder', ch.responderSend), responderRecv: ch.responderRecv,
  }
}

test('every pairing of ML-DSA-87 and ML-DSA-65 authenticates, each key pinned by the other side', async () => {
  for (const [iSet, rSet, i, r] of PAIRINGS) {
    const label = `${iSet} initiator, ${rSet} responder`
    const ch = makeInMemoryChannel()
    const [init, resp] = await Promise.all([
      initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: i, peerPublicKey: r.publicKey }),
      responderHandshake(ch.responderSend, ch.responderRecv, { identity: r, peerPublicKey: i.publicKey }),
    ])
    assert.deepEqual(init.txKey, resp.rxKey, label)
    assert.deepEqual(init.rxKey, resp.txKey, label)
    assert.ok(sameKey(init.peerPublicKey, r.publicKey), `${label}: the initiator reports the responder key`)
    assert.ok(sameKey(resp.peerPublicKey, i.publicKey), `${label}: the responder reports the initiator key`)
  }
})

test('each side declares its set in its hello, and two ML-DSA-65 ends send what 1.2.4 sends', async () => {
  // [ClientHello flags, ServerHello flags, initiator Finished, responder Finished]
  // A Finished frame on the wire is its plaintext plus a 16-byte GCM tag:
  // 7236 bytes for ML-DSA-87, 5278 for ML-DSA-65.
  const expected = {
    'ML-DSA-87 ML-DSA-87': [0x03, 0x07, 7236, 7236],
    'ML-DSA-87 ML-DSA-65': [0x03, 0x03, 7236, 5278],
    'ML-DSA-65 ML-DSA-87': [0x01, 0x05, 5278, 7236],
    'ML-DSA-65 ML-DSA-65': [0x01, 0x01, 5278, 5278],  // as 1.2.4
  }
  for (const [iSet, rSet, i, r] of PAIRINGS) {
    const ch = recordingChannel()
    await Promise.all([
      initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: i, kem: 'ml-kem-768' }),
      responderHandshake(ch.responderSend, ch.responderRecv, { identity: r }),
    ])
    const [clientHello, initFinished, ...moreI] = ch.sent.initiator
    const [serverHello, respFinished, ...moreR] = ch.sent.responder
    assert.equal(clientHello.length, 1218)
    assert.equal(serverHello.length, 1122)
    assert.deepEqual(moreI.concat(moreR), [], 'two messages each way')
    assert.deepEqual(
      [clientHello[1], serverHello[1], initFinished.length, respFinished.length],
      expected[`${iSet} ${rSet}`],
      `${iSet} initiator, ${rSet} responder`,
    )
  }
})

test('a pinned ML-DSA-87 key that does not match fails the handshake, on either side', async () => {
  for (const pinOn of ['initiator', 'responder']) {
    const ch = makeInMemoryChannel()
    const [init, resp] = await Promise.all([
      outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, {
        identity: initId87, handshakeTimeoutMs: 2000,
        ...(pinOn === 'initiator' && { peerPublicKey: relayId87.publicKey }),
      })),
      outcome(responderHandshake(ch.responderSend, ch.responderRecv, {
        identity: respId87, handshakeTimeoutMs: 2000,
        ...(pinOn === 'responder' && { peerPublicKey: relayId87.publicKey }),
      })),
    ])
    const pinned = pinOn === 'initiator' ? init : resp
    assert.ok(pinned.error instanceof KxcoPqTlsError, `the ${pinOn} refuses`)
    assert.match(pinned.error.message, /proved a different key from the pinned peerPublicKey/)
  }
})

test('a peer that declares a set other than its pinned key\'s is refused before this side signs', async () => {
  const t = { handshakeTimeoutMs: 300 }
  for (const [pinned, presented] of [[respId87, respId], [respId, respId87]]) {
    const want = pinned.publicKey.length === 2592 ? 'ML-DSA-87' : 'ML-DSA-65'
    const got  = want === 'ML-DSA-87' ? 'ML-DSA-65' : 'ML-DSA-87'

    // The initiator pins one set and the responder presents the other.
    let ch = recordingChannel()
    const [init] = await Promise.all([
      outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: initId87, peerPublicKey: pinned.publicKey, ...t })),
      outcome(responderHandshake(ch.responderSend, ch.responderRecv, { identity: presented, ...t })),
    ])
    assert.ok(init.error instanceof KxcoPqTlsError, 'the initiator refuses')
    assert.equal(init.error.message,
      `initiator: the peer declared ${got} and the pinned peerPublicKey is an ${want} key`)
    assert.equal(ch.sent.initiator.length, 1, 'the initiator sent its ClientHello and no Finished frame')

    // The responder pins one set and the initiator presents the other.
    ch = recordingChannel()
    const [, resp] = await Promise.all([
      outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: presented, ...t })),
      outcome(responderHandshake(ch.responderSend, ch.responderRecv, { identity: initId87, peerPublicKey: pinned.publicKey, ...t })),
    ])
    assert.ok(resp.error instanceof KxcoPqTlsError, 'the responder refuses')
    assert.equal(resp.error.message,
      `responder: the peer declared ${got} and the pinned peerPublicKey is an ${want} key`)
    assert.equal(ch.sent.responder.length, 0, 'the responder refused before answering')
  }
})

test('a key of any other length is refused, as an identity or as a pinned key, before anything is sent', async () => {
  const never = () => new Promise(() => {})
  const bytes = (n) => new Uint8Array(n)
  const cases = [
    // 1312 bytes is an ML-DSA-44 public key; 2591 and 2593 are one byte either side of ML-DSA-87.
    [{ identity: { publicKey: bytes(1312), secretKey: bytes(2560) } }, /identity\.publicKey must be an ML-DSA-87 \(2592-byte\) or ML-DSA-65 \(1952-byte\) public key, got 1312 bytes/],
    [{ identity: { publicKey: bytes(2591), secretKey: bytes(4896) } }, /identity\.publicKey must be .*got 2591 bytes/],
    [{ identity: { publicKey: 'not a key', secretKey: bytes(4896) } }, /identity\.publicKey must be .*got string/],
    [{ identity: { publicKey: initId87.publicKey, secretKey: initId.secretKey } }, /identity\.secretKey must be the 4896-byte ML-DSA-87 secret key/],
    [{ identity: { publicKey: initId.publicKey, secretKey: initId87.secretKey } }, /identity\.secretKey must be the 4032-byte ML-DSA-65 secret key/],
    [{ identity: initId87, peerPublicKey: bytes(2593) }, /peerPublicKey must be an ML-DSA-87 \(2592-byte\) or ML-DSA-65 \(1952-byte\) public key, got 2593 bytes/],
    [{ identity: initId, peerPublicKey: bytes(1312) }, /peerPublicKey must be .*got 1312 bytes/],
  ]
  for (const [options, message] of cases) {
    for (const handshake of [initiatorHandshake, responderHandshake]) {
      let sent = 0
      await assert.rejects(
        handshake(async () => { sent++ }, never, { ...options, handshakeTimeoutMs: 300 }),
        (err) => err instanceof KxcoPqTlsError && message.test(err.message),
        `${handshake.name}: ${message}`,
      )
      assert.equal(sent, 0, `${handshake.name} sent nothing`)
    }
  }
})

test('a hello changed in flight is refused: each signature covers both hellos and the sets they declare', async () => {
  // Bit 1 of the ServerHello echoes the initiator's set. Neither the session
  // keys nor the frame sizes depend on the echo, so the change reaches the
  // signatures and only they can refuse it.
  for (const [iSet, rSet, i, r] of PAIRINGS) {
    const label = `${iSet} initiator, ${rSet} responder`
    const ch = recordingChannel((role, index, data) => {
      if (role === 'responder' && index === 0) data[1] ^= 0x02
      return data
    })
    const [init, resp] = await Promise.all([
      outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: i, handshakeTimeoutMs: 2000 })),
      outcome(responderHandshake(ch.responderSend, ch.responderRecv, { identity: r, handshakeTimeoutMs: 2000 })),
    ])
    assert.ok(init.error instanceof KxcoPqTlsError, `${label}: the initiator refuses`)
    assert.match(init.error.message, /initiator: peer identity verification failed/, label)
    assert.ok(resp.error instanceof KxcoPqTlsError, `${label}: the responder refuses`)
    assert.match(resp.error.message, /responder: peer identity verification failed/, label)
  }
})

test('a set flag changed in flight is refused, by the side that reads the wrong frame and by the signature', async () => {
  const t = { handshakeTimeoutMs: 2000 }
  // ML-DSA-87 at both ends, and the ClientHello made to declare ML-DSA-65.
  let ch = recordingChannel((role, index, data) => {
    if (role === 'initiator' && index === 0) data[1] &= ~0x02
    return data
  })
  let [init, resp] = await Promise.all([
    outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: initId87, ...t })),
    outcome(responderHandshake(ch.responderSend, ch.responderRecv, { identity: respId87, ...t })),
  ])
  assert.match(resp.error?.message ?? '', /responder: the peer declared ML-DSA-65 and sent a Finished frame of 7220 bytes, not 5262/)
  assert.match(init.error?.message ?? '', /initiator: peer identity verification failed/)

  // ML-DSA-65 at both ends, and the ServerHello made to declare ML-DSA-87.
  ch = recordingChannel((role, index, data) => {
    if (role === 'responder' && index === 0) data[1] |= 0x04
    return data
  })
  ;[init, resp] = await Promise.all([
    outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: initId, ...t })),
    outcome(responderHandshake(ch.responderSend, ch.responderRecv, { identity: respId, ...t })),
  ])
  assert.match(init.error?.message ?? '', /initiator: the peer declared ML-DSA-87 and sent a Finished frame of 5262 bytes, not 7220/)
  assert.match(resp.error?.message ?? '', /responder: peer identity verification failed/)
})

test('a hello with a flag this version does not know is refused', async () => {
  const t = { handshakeTimeoutMs: 300 }
  let ch = recordingChannel((role, index, data) => {
    if (role === 'initiator' && index === 0) data[1] |= 0x04
    return data
  })
  const [, resp] = await Promise.all([
    outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: initId, kem: 'ml-kem-768', ...t })),
    outcome(responderHandshake(ch.responderSend, ch.responderRecv, { identity: respId, ...t })),
  ])
  assert.match(resp.error?.message ?? '', /ClientHello: unknown flags 0x5/)

  // Bit 3 in a ServerHello answering an ML-KEM-768 ClientHello.
  ch = recordingChannel((role, index, data) => {
    if (role === 'responder' && index === 0) data[1] |= 0x08
    return data
  })
  const [init] = await Promise.all([
    outcome(initiatorHandshake(ch.initiatorSend, ch.initiatorRecv, { identity: initId, kem: 'ml-kem-768', ...t })),
    outcome(responderHandshake(ch.responderSend, ch.responderRecv, { identity: respId, ...t })),
  ])
  assert.match(init.error?.message ?? '', /ServerHello: unknown flags 0x9/)
})

// ---------------------------------------------------------------------------
// ML-KEM-1024, and the handshake against 1.4.0 from npm
// ---------------------------------------------------------------------------

// A transport of a caller's own, as the handshake functions take one. On
// 'stream', recv(n) resolves with exactly n bytes however they were sent, as a
// socket read does. On 'messages', recv resolves with one whole message
// whatever n asks for, as a WebSocket does. close() fails the read waiting now
// and every read after it, as a closed connection does; bytes never read stay
// counted in unread(), and no read can reach them. `tamper(role, index, data)`
// may change each message on its way.
function rawLink(kind, tamper = (_role, _index, data) => data) {
  const pipe = () => ({ chunks: [], waiting: null, closed: false, reads: [] })
  const toResponder = pipe()
  const toInitiator = pipe()
  const sent = { initiator: [], responder: [] }
  const unreadIn = (p) => p.chunks.reduce((n, c) => n + c.length, 0)
  const settle = (p) => {
    if (!p.waiting) return
    const { n, resolve, reject } = p.waiting
    if (p.closed) { p.waiting = null; reject(new Error('the connection closed')); return }
    if (kind === 'messages') {
      if (p.chunks.length) { p.waiting = null; resolve(p.chunks.shift()) }
      return
    }
    if (unreadIn(p) < n) return
    p.waiting = null
    const all = Buffer.concat(p.chunks)
    p.chunks = all.length > n ? [all.subarray(n)] : []
    resolve(Buffer.from(all.subarray(0, n)))
  }
  const send = (role, p) => async (data) => {
    const index = sent[role].push(Buffer.from(data)) - 1
    if (p.closed) throw new Error('the connection closed')
    p.chunks.push(tamper(role, index, Buffer.from(data)))
    settle(p)
  }
  const recv = (p) => (n) => new Promise((resolve, reject) => {
    p.reads.push(n)
    p.waiting = { n, resolve, reject }
    settle(p)
  })
  return {
    sent,
    initiatorSend: send('initiator', toResponder), initiatorRecv: recv(toInitiator),
    responderSend: send('responder', toInitiator), responderRecv: recv(toResponder),
    responderReads: toResponder.reads,
    unread: () => ({ byResponder: unreadIn(toResponder), byInitiator: unreadIn(toInitiator) }),
    close() { for (const p of [toResponder, toInitiator]) { p.closed = true; settle(p) } },
  }
}

// A side that closes the link when its handshake fails, as wrapStream and
// wrapWebSocket close theirs.
const closesOnFailure = (link, p) => p.catch((err) => { link.close(); throw err })

const LINKS = ['stream', 'messages']
const IDENTITIES = [
  ['no identities', {}, {}],
  ['ML-DSA-87 identities', { identity: initId87 }, { identity: respId87 }],
]
const quick = { handshakeTimeoutMs: 3000 }

test('an initiator on 1.4.0 reaches this responder on ML-KEM-768, with the same keys, on a byte stream and on messages', async () => {
  for (const kind of LINKS) {
    for (const [label, i, r] of IDENTITIES) {
      const what = `${kind}, ${label}`
      const link = rawLink(kind)
      const [init, resp] = await Promise.all([
        v140.initiatorHandshake(link.initiatorSend, link.initiatorRecv, { ...quick, ...i }),
        responderHandshake(link.responderSend, link.responderRecv, { ...quick, ...r }),
      ])
      assert.deepEqual(init.txKey, resp.rxKey, what)
      assert.deepEqual(init.rxKey, resp.txKey, what)
      assert.equal(link.sent.initiator[0].length, 1218, what)
      assert.equal(link.sent.responder[0].length, 1122, what)
      assert.equal(link.sent.responder[0][1] & 0x08, 0, `${what}: the ServerHello declares ML-KEM-768`)
      if (i.identity) assert.ok(sameKey(resp.peerPublicKey, i.identity.publicKey), what)
    }
  }
})

test('this initiator given kem: ml-kem-768 reaches a 1.4.0 responder with the same keys', async () => {
  for (const kind of LINKS) {
    for (const kem of [{ kem: 'ml-kem-768' }]) {
      for (const [label, i, r] of IDENTITIES) {
        const what = `${kind}, ${kem.kem ?? 'default'}, ${label}`
        const link = rawLink(kind)
        const [init, resp] = await Promise.all([
          initiatorHandshake(link.initiatorSend, link.initiatorRecv, { ...quick, ...kem, ...i }),
          v140.responderHandshake(link.responderSend, link.responderRecv, { ...quick, ...r }),
        ])
        assert.deepEqual(init.txKey, resp.rxKey, what)
        assert.deepEqual(init.rxKey, resp.txKey, what)
        assert.equal(link.sent.initiator[0].length, 1218, what)
        assert.equal(link.sent.initiator[0][1] & 0x08, 0, `${what}: the ClientHello declares ML-KEM-768`)
        if (r.identity) assert.ok(sameKey(init.peerPublicKey, r.identity.publicKey), what)
      }
    }
  }
})

// What a 2.0.0 initiator raises when the connection closes after its
// ML-KEM-1024 hello, before any ServerHello.
const CLOSED_AFTER_1024 = 'the responder closed after an ML-KEM-1024 hello; a responder on ' +
  "kxco-pq-tls 1.4 or earlier cannot read it: upgrade it, or pass kem: 'ml-kem-768'"
// What it raises when the deadline passes before a usable ServerHello.
const NO_SERVER_HELLO_1024 = 'no valid ML-KEM-1024 ServerHello before the deadline; likely cause: a responder on ' +
  'kxco-pq-tls 1.2.4 or earlier ignores the ML-KEM-1024 flag, and one on 1.3 or 1.4 refuses it: ' +
  "upgrade the responder, or pass kem: 'ml-kem-768'"

test('this initiator on ML-KEM-1024, by default or by name, meets a 1.4.0 responder: refused, nothing answered, and the initiator says why', async () => {
  for (const kind of LINKS) {
    for (const kem of [{}, { kem: 'ml-kem-1024' }]) {
      const what = `${kind}, ${kem.kem ?? 'default'}`
      const link = rawLink(kind)
      const started = Date.now()
      const [init, resp] = await Promise.all([
        outcome(initiatorHandshake(link.initiatorSend, link.initiatorRecv, { ...quick, ...kem })),
        outcome(closesOnFailure(link, v140.responderHandshake(link.responderSend, link.responderRecv, quick))),
      ])
      // On a byte stream it reads 1218 bytes and refuses the flag; on messages
      // the whole 1602-byte hello arrives and it refuses the length.
      assert.equal(resp.error?.message,
        kind === 'stream' ? 'ClientHello: unknown flags 0x8' : 'ClientHello: expected 1218 bytes, got 1602', what)
      assert.equal(link.sent.initiator[0].length, 1602, what)
      assert.deepEqual(link.responderReads, [1218], `${what}: the responder read once`)
      assert.equal(link.sent.responder.length, 0, `${what}: the responder answered nothing`)
      // On a byte stream the 384 bytes behind its read are never read: the link
      // is closed, so no read reaches them.
      assert.deepEqual(link.unread(), { byResponder: kind === 'stream' ? 384 : 0, byInitiator: 0 }, what)
      await assert.rejects(link.responderRecv(384), /the connection closed/)
      // The initiator learns of it from the close, at once, not at its deadline,
      // and says what the close most likely means, keeping the close as cause.
      assert.ok(init.error instanceof KxcoPqTlsError, what)
      assert.equal(init.error.code, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024, what)
      assert.equal(init.error.message, CLOSED_AFTER_1024, what)
      assert.equal(init.error.cause?.message, 'the connection closed', what)
      assert.ok(Date.now() - started < 2000, `${what}: the initiator waited ${Date.now() - started}ms`)
    }
  }

  // A close after an ML-KEM-768 hello is reported as the transport reports it.
  const link = rawLink('stream')
  const [init] = await Promise.all([
    outcome(initiatorHandshake(link.initiatorSend, link.initiatorRecv, { ...quick, kem: 'ml-kem-768' })),
    outcome(closesOnFailure(link, responderHandshake(link.responderSend, link.responderRecv, { ...quick, identity: respId87 }))),
  ])
  assert.equal(init.error?.message, 'the connection closed')
  assert.equal(init.error?.code, undefined)

  // A responder that never answers an ML-KEM-1024 hello is the deadline case,
  // not a close.
  const never = () => new Promise(() => {})
  const late = await initiatorHandshake(async () => {}, never, { handshakeTimeoutMs: 100 }).then(() => null, (e) => e)
  assert.equal(late?.message, NO_SERVER_HELLO_1024)
  assert.equal(late?.cause?.code, ERR_HANDSHAKE_TIMEOUT)
})

test('this initiator on ML-KEM-1024, by default or by name, meets a 1.2.4 responder: on a byte stream it answers ML-KEM-768 and the initiator explains the deadline', async () => {
  const deadline = 500
  for (const kind of LINKS) {
    for (const kem of [{}, { kem: 'ml-kem-1024' }]) {
      const what = `${kind}, ${kem.kem ?? 'default'}`
      const link = rawLink(kind)
      const started = Date.now()
      const [init, resp] = await Promise.all([
        outcome(initiatorHandshake(link.initiatorSend, link.initiatorRecv, { handshakeTimeoutMs: deadline, ...kem })),
        outcome(closesOnFailure(link, v124.responderHandshake(link.responderSend, link.responderRecv, quick))),
      ])
      const elapsed = Date.now() - started
      assert.equal(link.sent.initiator[0].length, 1602, what)
      assert.ok(init.error instanceof KxcoPqTlsError, what)
      assert.equal(init.error.code, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024, what)
      if (kind === 'stream') {
        // 1.2.4 does not check the flag: it reads 1218 bytes, takes them for an
        // ML-KEM-768 hello and answers with a 1122-byte ServerHello, believing
        // the handshake complete. The initiator waits for the rest of a
        // 1602-byte one until its deadline, then says why.
        assert.ifError(resp.error)
        assert.deepEqual(link.sent.responder.map((m) => m.length), [1122], what)
        assert.equal(init.error.message, NO_SERVER_HELLO_1024, what)
        assert.equal(init.error.cause?.code, ERR_HANDSHAKE_TIMEOUT, what)
        assert.ok(elapsed >= deadline && elapsed < deadline + 1500, `${what}: failed after ${elapsed}ms`)
      } else {
        // On messages 1.2.4 refuses the hello's length and the link closes.
        assert.equal(resp.error?.message, 'ClientHello: expected 1218 bytes, got 1602', what)
        assert.equal(link.sent.responder.length, 0, what)
        assert.equal(init.error.message, CLOSED_AFTER_1024, what)
        assert.equal(init.error.cause?.message, 'the connection closed', what)
        assert.ok(elapsed < deadline, `${what}: failed after ${elapsed}ms`)
      }
    }
  }

  // kem: 'ml-kem-768' reaches it, with the same keys.
  const link = rawLink('stream')
  const [init, resp] = await Promise.all([
    initiatorHandshake(link.initiatorSend, link.initiatorRecv, { ...quick, kem: 'ml-kem-768' }),
    v124.responderHandshake(link.responderSend, link.responderRecv, quick),
  ])
  assert.deepEqual(init.txKey, resp.rxKey)
  assert.deepEqual(init.rxKey, resp.txKey)

  // An ML-KEM-768 initiator whose peer is too slow still gets the plain timeout.
  const slow = rawLink('stream')
  const plain = await initiatorHandshake(slow.initiatorSend, slow.initiatorRecv, { handshakeTimeoutMs: 100, kem: 'ml-kem-768' })
    .then(() => null, (e) => e)
  assert.equal(plain?.code, ERR_HANDSHAKE_TIMEOUT)
  assert.equal(plain?.cause, undefined)
})

test('through the handshake functions, a 1218-byte hello declaring ML-KEM-1024 is read as on a stream, because a custom recv may be one', async () => {
  // A caller's recv may return n bytes or one message, and this side cannot
  // tell which, so it asks for the 384 bytes a stream would still hold. On a
  // message transport of the caller's own they never come, and the
  // responder's deadline ends the wait. wrapWebSocket refuses such a hello at
  // once instead; see websocket.test.js.
  const link = rawLink('messages', (role, index, data) => {
    if (role === 'initiator' && index === 0) data[1] |= 0x08
    return data
  })
  const [, resp] = await Promise.all([
    outcome(initiatorHandshake(link.initiatorSend, link.initiatorRecv, { handshakeTimeoutMs: 300, kem: 'ml-kem-768' })),
    outcome(responderHandshake(link.responderSend, link.responderRecv, { handshakeTimeoutMs: 200 })),
  ])
  assert.deepEqual(link.responderReads, [1218, 384])
  assert.equal(resp.error?.code, ERR_HANDSHAKE_TIMEOUT)
})

test('two ends on this version agree ML-KEM-1024, by default or by name: 1602-byte hellos both ways, the flag declared and echoed', async () => {
  // [ClientHello flags, ServerHello flags] for each pairing of identities.
  const flags = { 'no identities': [0x08, 0x08], 'ML-DSA-87 identities': [0x0b, 0x0f] }
  for (const kind of LINKS) {
    for (const [label, i, r] of IDENTITIES) {
      for (const kem of [{}, { kem: 'ml-kem-1024' }]) {
        const what = `${kind}, ${label}, ${kem.kem ?? 'default'}`
        const link = rawLink(kind)
        const [init, resp] = await Promise.all([
          initiatorHandshake(link.initiatorSend, link.initiatorRecv, { ...quick, ...kem, ...i }),
          responderHandshake(link.responderSend, link.responderRecv, { ...quick, ...r }),
        ])
        assert.deepEqual(init.txKey, resp.rxKey, what)
        assert.deepEqual(init.rxKey, resp.txKey, what)
        const [clientHello] = link.sent.initiator
        const [serverHello] = link.sent.responder
        assert.equal(clientHello.length, 1602, what)
        assert.equal(serverHello.length, 1602, what)
        assert.deepEqual([clientHello[1], serverHello[1]], flags[label], what)
        // A byte stream gives the responder the 1218 bytes it asks for first,
        // then the 384 the flag says follow; messages give it the whole hello.
        assert.deepEqual(link.responderReads.slice(0, 2),
          kind === 'stream' ? [1218, 384] : [1218, ...(i.identity ? [7236] : [])], what)
        if (i.identity) {
          assert.ok(sameKey(init.peerPublicKey, r.identity.publicKey), what)
          assert.ok(sameKey(resp.peerPublicKey, i.identity.publicKey), what)
        }
      }
    }
  }
})

test('with mutual authentication, the ML-KEM-1024 flag flipped in flight fails the Finished check', async () => {
  const opts = { handshakeTimeoutMs: 2000 }
  for (const kind of LINKS) {
    // The ServerHello's echo, cleared on its way. The initiator's sizes and
    // keys follow from its own choice, so the session keys agree, and only the
    // signatures over both hellos can refuse it.
    const link = rawLink(kind, (role, index, data) => {
      if (role === 'responder' && index === 0) data[1] ^= 0x08
      return data
    })
    const [init, resp] = await Promise.all([
      outcome(initiatorHandshake(link.initiatorSend, link.initiatorRecv, { ...opts, identity: initId87, kem: 'ml-kem-1024' })),
      outcome(responderHandshake(link.responderSend, link.responderRecv, { ...opts, identity: respId87 })),
    ])
    assert.match(init.error?.message ?? '', /initiator: peer identity verification failed/, kind)
    assert.match(resp.error?.message ?? '', /responder: peer identity verification failed/, kind)
  }

  // The ClientHello's flag, cleared on its way. On a byte stream the responder
  // reads an ML-KEM-768 hello, and the 384 bytes behind it break the
  // initiator's Finished frame. On messages the length refuses it first.
  for (const kind of LINKS) {
    const link = rawLink(kind, (role, index, data) => {
      if (role === 'initiator' && index === 0) data[1] ^= 0x08
      return data
    })
    const [init, resp] = await Promise.all([
      outcome(closesOnFailure(link, initiatorHandshake(link.initiatorSend, link.initiatorRecv, { ...opts, identity: initId87, kem: 'ml-kem-1024' }))),
      outcome(closesOnFailure(link, responderHandshake(link.responderSend, link.responderRecv, { ...opts, identity: respId87 }))),
    ])
    assert.equal(resp.error?.message,
      kind === 'stream' ? 'frame authentication failed' : 'ClientHello: expected 1218 bytes, got 1602', kind)
    assert.ok(init.error, `${kind}: the initiator does not complete`)
  }
})

test('an ML-KEM-1024 hello with a flag this version does not know is refused', async () => {
  for (const kind of LINKS) {
    let link = rawLink(kind, (role, index, data) => {
      if (role === 'initiator' && index === 0) data[1] |= 0x10
      return data
    })
    const [, resp] = await Promise.all([
      outcome(closesOnFailure(link, initiatorHandshake(link.initiatorSend, link.initiatorRecv, { ...quick, kem: 'ml-kem-1024' }))),
      outcome(closesOnFailure(link, responderHandshake(link.responderSend, link.responderRecv, quick))),
    ])
    assert.equal(resp.error?.message, 'ClientHello: unknown flags 0x18', kind)

    link = rawLink(kind, (role, index, data) => {
      if (role === 'responder' && index === 0) data[1] |= 0x10
      return data
    })
    const [init] = await Promise.all([
      outcome(closesOnFailure(link, initiatorHandshake(link.initiatorSend, link.initiatorRecv, { ...quick, kem: 'ml-kem-1024' }))),
      outcome(closesOnFailure(link, responderHandshake(link.responderSend, link.responderRecv, quick))),
    ])
    assert.equal(init.error?.message, 'ServerHello: unknown flags 0x18', kind)
  }
})

test('a kem option that names no ML-KEM set is refused before anything is sent', async () => {
  const never = () => new Promise(() => {})
  const cases = [['ml-kem-512', "'ml-kem-512'"], ['ML-KEM-1024', "'ML-KEM-1024'"], [1024, 'number'], [null, 'object']]
  for (const [kem, shown] of cases) {
    let sent = 0
    await assert.rejects(
      initiatorHandshake(async () => { sent++ }, never, { kem, handshakeTimeoutMs: 300 }),
      (err) => err instanceof KxcoPqTlsError &&
        err.message === `kem must be 'ml-kem-768' or 'ml-kem-1024', got ${shown}`,
      String(kem),
    )
    assert.equal(sent, 0, `${String(kem)}: nothing sent`)
  }
})
