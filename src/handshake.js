/**
 * kxco-pq-tls handshake protocol v1
 *
 * ClientHello (1218 bytes):
 *   [1]    version = 0x01
 *   [1]    flags   (bit 0 = mutual_auth_requested,
 *                   bit 1 = the initiator signs with ML-DSA-87)
 *   [1184] ML-KEM-768 ephemeral encap key
 *   [32]   X25519 ephemeral public key
 *
 * ServerHello (1122 bytes):
 *   [1]    version = 0x01
 *   [1]    flags   (bits 0 and 1 echo the ClientHello,
 *                   bit 2 = the responder signs with ML-DSA-87)
 *   [1088] ML-KEM-768 ciphertext
 *   [32]   X25519 ephemeral public key
 *
 * Session keys: HKDF(ss_kem || ss_dh, salt=c_x25519_pk||s_x25519_pk, info="kxco-pq-tls-v1")
 * then split into keyC2S and keyS2C.
 *
 * If mutual auth requested, after key establishment both sides exchange a
 * Finished frame (sent encrypted over the new session) containing their
 * ML-DSA identity public key and a signature over
 * SHA-256(label || SHA-256(clientHello||serverHello)), where the label names the
 * side that signs: "kxco-pq-tls-v1-finished-initiator" or
 * "kxco-pq-tls-v1-finished-responder". A Finished frame is therefore never
 * valid in the other direction, even between two ends that share one key.
 * A responder holding an identity requires the request: it refuses a
 * ClientHello without the flag before answering it.
 *
 * Each side signs with the ML-DSA parameter set (FIPS 204) its own identity
 * key belongs to, and the key's length decides it: a 2592-byte public key is
 * ML-DSA-87 and a 1952-byte one is ML-DSA-65. Any other length is refused
 * before anything is sent. The two sides may use different sets. Each side
 * declares its set in a flag of the hello it sends, which tells the peer the
 * size of the Finished frame to read before it can decrypt it. Both hellos are
 * inside the transcript both sides sign, so each signature covers the set each
 * side declared, and a Finished frame must carry a key of the set its sender
 * declared. A pinned peerPublicKey fixes the set the peer must declare. With
 * ML-DSA-65 on both sides the set flags are clear, and every message has the
 * layout and flags that 1.2.4 sends.
 *
 * The verified peer key is returned as `peerPublicKey`. A valid signature
 * proves the peer holds the private half of the key it sent, not which key
 * that is, so `options.peerPublicKey` pins the key the peer must prove.
 *
 * Finished plaintext (7220 bytes for ML-DSA-87, 5262 for ML-DSA-65):
 *   [1]    msg_type = 0x01
 *   [2592 or 1952] the sender's ML-DSA-87 or ML-DSA-65 public key
 *   [4627 or 3309] its signature over SHA-256(label || SHA-256(clientHello || serverHello))
 */

import {
  generateKemKeypair, generateX25519Keypair,
  kemEncapsulate, kemDecapsulate, x25519DH,
  deriveKeys, sealFrame, openFrame,
  dsaSign, dsaVerify, dsaSetOf, ML_DSA_87, ML_DSA_65, sha256,
} from './primitives.js'
import { KxcoPqTlsError, ERR_HANDSHAKE_TIMEOUT } from './errors.js'

const VERSION      = 0x01
const FLAG_AUTH    = 0x01
// The set each side signs with, declared in the hello it sends. Clear for
// ML-DSA-65, so two ML-DSA-65 ends send exactly the flags 1.2.4 sends.
const FLAG_INITIATOR_87 = 0x02   // ClientHello, echoed in the ServerHello
const FLAG_RESPONDER_87 = 0x04   // ServerHello
const MSG_FINISHED = 0x01

// What each side signs names that side, so a Finished frame sent back to the
// side that made it does not verify as the other side's.
const FINISHED_LABEL = {
  initiator: new TextEncoder().encode('kxco-pq-tls-v1-finished-initiator'),
  responder: new TextEncoder().encode('kxco-pq-tls-v1-finished-responder'),
}

/**
 * A handshake is four small messages and a few milliseconds of arithmetic. It
 * takes 30 seconds only when the peer is never going to answer, so waiting
 * forever is never the useful behaviour.
 *
 * The specific case this exists for: an initiator configured with an identity
 * expects a Finished frame, and a responder with no identity of its own never
 * sends one. Both sides believe they are fine and the initiator waits. Nothing
 * in this package could time that out before, because `recv` belongs to the
 * caller.
 *
 * Pass `handshakeTimeoutMs: 0` to restore the old unbounded behaviour.
 */
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 30_000

/**
 * A total deadline for the handshake, not a per-message one. A per-message
 * timer would let a peer that dribbles bytes hold the connection open
 * indefinitely by resetting the clock on every frame.
 */
function withDeadline(ms) {
  if (!ms || ms <= 0) return { guard: (p) => p, done: () => {} }

  let timer
  const expired = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new KxcoPqTlsError(
        `handshake did not complete within ${ms}ms. The peer accepted the ` +
        'connection and then did not send the frame this side was waiting ' +
        'for. The usual cause is a configuration mismatch: this side was ' +
        'given an identity and the peer was not, so the peer completed its ' +
        'handshake and never sent a Finished frame, or the peer was given ' +
        'one and this side was not, so the peer refused the handshake and ' +
        'left the connection open. A peer speaking a ' +
        'different protocol fails earlier and differently, with a version or ' +
        'length error rather than this.',
        ERR_HANDSHAKE_TIMEOUT,
      ))
    }, ms)
    // Deliberately NOT unref'd. An unref'd timer cannot hold the event loop
    // open, so in a process where the handshake is the only pending work the
    // loop drains and this timer never fires: the deadline silently does
    // nothing, which is the exact hang it exists to prevent. It was unref'd
    // in 1.2.2 and every deadline test failed on Node 20 and 22 with
    // "Promise resolution is still pending but the event loop has already
    // resolved". Node 24 masked it. Holding the loop open is bounded, because
    // both handshakes clear this timer in a finally block.
  })
  // The race leaves this promise rejected and unobserved once the handshake
  // wins, which Node reports as an unhandled rejection. Observe it here.
  expired.catch(() => {})

  return {
    guard: (p) => Promise.race([p, expired]),
    done: () => clearTimeout(timer),
  }
}

const CLIENT_HELLO_SIZE = 1218   // 1 + 1 + 1184 + 32
const SERVER_HELLO_SIZE = 1122   // 1 + 1 + 1088 + 32

// Finished plaintext: message type, public key, signature.
// 7220 bytes for ML-DSA-87 (1 + 2592 + 4627), 5262 for ML-DSA-65 (1 + 1952 + 3309).
const finishedSize = (set) => 1 + set.publicKey + set.signature

/**
 * Perform handshake as initiator.
 * send(buf)  → Promise<void>   — write one framed message
 * recv(n)    → Promise<Buffer> — read exactly n bytes (stream) or one message (WS)
 * options.identity: optional { publicKey, secretKey }, ML-DSA-87 or ML-DSA-65, for mutual auth
 * options.peerPublicKey: optional ML-DSA-87 or ML-DSA-65 public key the peer must prove
 * Returns { txKey, rxKey } — tx is initiator→responder (C2S), rx is S2C
 * The result also carries peerPublicKey, the key the peer proved, or undefined
 * without mutual auth.
 */
export async function initiatorHandshake(send, recv, options = {}) {
  const ownSet    = identitySet(options.identity)
  const pinnedSet = checkPinnedKeyOption(options)
  const deadline = withDeadline(options.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS)
  try {
    const kem  = generateKemKeypair()
    const dh   = generateX25519Keypair()
    const flags = !ownSet ? 0x00 : FLAG_AUTH | (ownSet === ML_DSA_87 ? FLAG_INITIATOR_87 : 0)

    const clientHello = buildClientHello(flags, kem.publicKey, dh.publicKey)
    await deadline.guard(send(clientHello))

    const serverHello = await deadline.guard(recv(SERVER_HELLO_SIZE))
    validateHello(serverHello, SERVER_HELLO_SIZE, 'ServerHello',
      FLAG_AUTH | FLAG_INITIATOR_87 | FLAG_RESPONDER_87)

    const kemCt       = serverHello.slice(2, 2 + 1088)
    const serverX25519 = serverHello.slice(2 + 1088)

    const ssKem = kemDecapsulate(kemCt, kem.secretKey)
    const ssDh  = x25519DH(dh.secretKey, serverX25519)
    const salt  = concat(dh.publicKey, serverX25519)
    const { keyC2S, keyS2C } = deriveKeys(ssKem, ssDh, salt)

    let peerPublicKey
    if (options.identity) {
      const peerSet = serverHello[1] & FLAG_RESPONDER_87 ? ML_DSA_87 : ML_DSA_65
      checkPinnedSet(peerSet, pinnedSet, 'initiator')
      const transcript = sha256.create()
        .update(clientHello).update(serverHello).digest()
      peerPublicKey = await exchangeFinished(
        send, recv, keyC2S, keyS2C, options.identity, ownSet, peerSet, transcript, 'initiator', deadline,
      )
      checkPinnedKey(peerPublicKey, options.peerPublicKey, 'initiator')
    }

    return { txKey: keyC2S, rxKey: keyS2C, peerPublicKey }
  } finally {
    deadline.done()
  }
}

/**
 * Perform handshake as responder.
 * Returns { txKey, rxKey } — tx is responder→initiator (S2C), rx is C2S
 * The result also carries peerPublicKey, as for the initiator.
 */
export async function responderHandshake(send, recv, options = {}) {
  const ownSet    = identitySet(options.identity)
  const pinnedSet = checkPinnedKeyOption(options)
  const deadline = withDeadline(options.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS)
  try {
    const clientHello = await deadline.guard(recv(CLIENT_HELLO_SIZE))
    validateHello(clientHello, CLIENT_HELLO_SIZE, 'ClientHello', FLAG_AUTH | FLAG_INITIATOR_87)

    const flags        = clientHello[1]
    // A responder given an identity authenticates every initiator, so it does
    // not answer one that has not asked to authenticate.
    if (options.identity && !(flags & FLAG_AUTH))
      throw new KxcoPqTlsError(
        'responder: this side holds an identity and the initiator did not request mutual authentication',
      )
    // Nor one that has declared a set other than the pinned key's.
    const peerSet = flags & FLAG_INITIATOR_87 ? ML_DSA_87 : ML_DSA_65
    checkPinnedSet(peerSet, pinnedSet, 'responder')
    const clientKemEk  = clientHello.slice(2, 2 + 1184)
    const clientX25519 = clientHello.slice(2 + 1184)

    const { ciphertext, sharedSecret: ssKem } = kemEncapsulate(clientKemEk)
    const dh  = generateX25519Keypair()
    const ssDh = x25519DH(dh.secretKey, clientX25519)
    const salt = concat(clientX25519, dh.publicKey)
    const { keyC2S, keyS2C } = deriveKeys(ssKem, ssDh, salt)

    const serverFlags = ownSet === ML_DSA_87 ? flags | FLAG_RESPONDER_87 : flags
    const serverHello = buildServerHello(serverFlags, ciphertext, dh.publicKey)
    await deadline.guard(send(serverHello))

    let peerPublicKey
    if ((flags & FLAG_AUTH) && options.identity) {
      const transcript = sha256.create()
        .update(clientHello).update(serverHello).digest()
      peerPublicKey = await exchangeFinished(
        send, recv, keyS2C, keyC2S, options.identity, ownSet, peerSet, transcript, 'responder', deadline,
      )
      checkPinnedKey(peerPublicKey, options.peerPublicKey, 'responder')
    }

    return { txKey: keyS2C, rxKey: keyC2S, peerPublicKey }
  } finally {
    deadline.done()
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function buildClientHello(flags, kemEk, x25519Pk) {
  const buf = new Uint8Array(CLIENT_HELLO_SIZE)
  buf[0] = VERSION
  buf[1] = flags
  buf.set(kemEk,    2)
  buf.set(x25519Pk, 2 + 1184)
  return Buffer.from(buf)
}

function buildServerHello(flags, kemCt, x25519Pk) {
  const buf = new Uint8Array(SERVER_HELLO_SIZE)
  buf[0] = VERSION
  buf[1] = flags
  buf.set(kemCt,    2)
  buf.set(x25519Pk, 2 + 1088)
  return Buffer.from(buf)
}

function validateHello(buf, expectedLen, name, knownFlags) {
  if (buf.length !== expectedLen)
    throw new KxcoPqTlsError(`${name}: expected ${expectedLen} bytes, got ${buf.length}`)
  if (buf[0] !== VERSION)
    throw new KxcoPqTlsError(`${name}: unsupported version 0x${buf[0].toString(16)}`)
  // A flag can change what follows, such as the size of a Finished frame, so
  // one this version does not know is refused rather than ignored.
  if (buf[1] & ~knownFlags)
    throw new KxcoPqTlsError(`${name}: unknown flags 0x${buf[1].toString(16)}`)
}

async function exchangeFinished(
  send, recv, txKey, rxKey, identity, ownSet, peerSet, transcript, role,
  deadline = { guard: (p) => p },
) {
  // Send our Finished first, then receive theirs.
  // The encrypted sequence starts at 0 for each direction.
  const sig      = dsaSign(ownSet, identity.secretKey, finishedDigest(role, transcript))
  const finished = buildFinished(ownSet, identity.publicKey, sig)
  await deadline.guard(send(sealFrame(txKey, 0, finished)))

  // The wait that used to be unbounded. A responder without an identity of its
  // own never sends this frame, so without a deadline the initiator sits here.
  // Its size follows from the set the peer declared in its hello.
  const rxBuf     = await deadline.guard(recv(finishedSize(peerSet) + 16))  // +16 GCM tag
  const plaintext = openFrame(rxKey, 0, Buffer.from(rxBuf))
  const peer = role === 'initiator' ? 'responder' : 'initiator'
  return verifyFinished(plaintext, peerSet, finishedDigest(peer, transcript), role)
}

function finishedDigest(signer, transcript) {
  return sha256.create().update(FINISHED_LABEL[signer]).update(transcript).digest()
}

function buildFinished(set, identityPk, sig) {
  const buf = new Uint8Array(finishedSize(set))
  buf[0] = MSG_FINISHED
  buf.set(identityPk, 1)
  buf.set(sig, 1 + set.publicKey)
  return buf
}

function verifyFinished(plaintext, set, signed, role) {
  if (plaintext[0] !== MSG_FINISHED)
    throw new KxcoPqTlsError('unexpected finished message type')
  // The peer declared its set in a hello its signature covers. A frame of any
  // other size is refused, never read as a key of the other set.
  if (plaintext.length !== finishedSize(set))
    throw new KxcoPqTlsError(
      `${role}: the peer declared ${set.name} and sent a Finished frame of ${plaintext.length} bytes, not ${finishedSize(set)}`,
    )
  const identityPk = plaintext.slice(1, 1 + set.publicKey)
  const sig        = plaintext.slice(1 + set.publicKey)
  if (!dsaVerify(set, identityPk, signed, sig))
    throw new KxcoPqTlsError(`${role}: peer identity verification failed`)
  return identityPk
}

const sizeOf = (key) => (key instanceof Uint8Array ? `${key.length} bytes` : typeof key)

// The set this side signs with, named by the length of its own public key.
// Checked before anything is sent, so a key of the wrong size fails here with
// a reason, not at the peer as a signature that does not verify.
function identitySet(identity) {
  if (!identity) return undefined
  const set = dsaSetOf(identity.publicKey)
  if (!set)
    throw new KxcoPqTlsError(
      'identity.publicKey must be an ML-DSA-87 (2592-byte) or ML-DSA-65 (1952-byte) ' +
      `public key, got ${sizeOf(identity.publicKey)}`,
    )
  const sk = identity.secretKey
  if (!(sk instanceof Uint8Array) || sk.length !== set.secretKey)
    throw new KxcoPqTlsError(
      `identity.secretKey must be the ${set.secretKey}-byte ${set.name} secret key ` +
      `that matches identity.publicKey, got ${sizeOf(sk)}`,
    )
  return set
}

// A pinned key is checked only in a mutual handshake, and this side asks for
// one only when it holds an identity, so a pin without an identity would never
// be checked. Refuse it rather than connect unverified. Returns the set the
// pinned key belongs to.
function checkPinnedKeyOption(options) {
  if (options.peerPublicKey === undefined) return undefined
  if (!options.identity)
    throw new KxcoPqTlsError(
      'peerPublicKey needs an identity on this side too: the peer proves its key only in a mutual handshake',
    )
  const set = dsaSetOf(options.peerPublicKey)
  if (!set)
    throw new KxcoPqTlsError(
      'peerPublicKey must be an ML-DSA-87 (2592-byte) or ML-DSA-65 (1952-byte) ' +
      `public key, got ${sizeOf(options.peerPublicKey)}`,
    )
  return set
}

// A pinned key fixes the set the peer must sign with. A peer that declares the
// other set cannot prove the pinned key, so it is refused before its Finished
// frame is read.
function checkPinnedSet(peerSet, pinnedSet, role) {
  if (pinnedSet !== undefined && peerSet !== pinnedSet)
    throw new KxcoPqTlsError(
      `${role}: the peer declared ${peerSet.name} and the pinned peerPublicKey is an ${pinnedSet.name} key`,
    )
}

function checkPinnedKey(peerPublicKey, pinned, role) {
  if (pinned !== undefined && Buffer.compare(peerPublicKey, pinned) !== 0)
    throw new KxcoPqTlsError(`${role}: the peer proved a different key from the pinned peerPublicKey`)
}

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) { out.set(a, off); off += a.length }
  return out
}
