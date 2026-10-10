/**
 * kxco-pq-tls handshake protocol v1
 *
 * ClientHello (1218 bytes, or 1602 with ML-KEM-1024):
 *   [1]    version = 0x01
 *   [1]    flags   (bit 0 = mutual_auth_requested,
 *                   bit 1 = the initiator signs with ML-DSA-87,
 *                   bit 3 = ML-KEM-1024)
 *   [1184] ML-KEM-768 ephemeral encap key, or [1568] ML-KEM-1024
 *   [32]   X25519 ephemeral public key
 *
 * ServerHello (1122 bytes, or 1602 with ML-KEM-1024):
 *   [1]    version = 0x01
 *   [1]    flags   (bits 0, 1 and 3 echo the ClientHello,
 *                   bit 2 = the responder signs with ML-DSA-87)
 *   [1088] ML-KEM-768 ciphertext, or [1568] ML-KEM-1024
 *   [32]   X25519 ephemeral public key
 *
 * Session keys: HKDF(ss_kem || ss_dh, salt=c_x25519_pk||s_x25519_pk, info="kxco-pq-tls-v1")
 * then split into keyC2S and keyS2C. With ML-KEM-1024 the info is
 * "kxco-pq-tls-v1-ml-kem-1024".
 *
 * The initiator chooses the ML-KEM set (FIPS 203) and the responder answers in
 * it. Without bit 3 every message, flag and key is what 1.4.0 sends and
 * derives. A responder on 1.4.0 or earlier cannot read an ML-KEM-1024 hello.
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
  ML_KEM_768, ML_KEM_1024,
} from './primitives.js'
import { KxcoPqTlsError, ERR_HANDSHAKE_TIMEOUT, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024 } from './errors.js'

// Set in the options by wrapWebSocket, never by a caller: the transport hands
// over one whole message per read. Not exported from the package.
export const MESSAGE_TRANSPORT = Symbol('kxco-pq-tls message transport')

const VERSION      = 0x01
const FLAG_AUTH    = 0x01
// The set each side signs with, declared in the hello it sends. Clear for
// ML-DSA-65, so two ML-DSA-65 ends send exactly the flags 1.2.4 sends.
const FLAG_INITIATOR_87 = 0x02   // ClientHello, echoed in the ServerHello
const FLAG_RESPONDER_87 = 0x04   // ServerHello
// The ML-KEM set the initiator chose, declared in the ClientHello and echoed in
// the ServerHello. Clear for ML-KEM-768, so those hellos are what 1.4.0 sends.
const FLAG_KEM_1024 = 0x08
const MSG_FINISHED = 0x01

// The `kem` option. An initiator sends ML-KEM-1024 unless told otherwise.
const KEM_SETS = new Map([['ml-kem-768', ML_KEM_768], ['ml-kem-1024', ML_KEM_1024]])
const DEFAULT_KEM = ML_KEM_1024

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

// Version, flags, the ML-KEM encapsulation key or ciphertext, the X25519 key.
// 1218 and 1122 bytes with ML-KEM-768 (1 + 1 + 1184 + 32, 1 + 1 + 1088 + 32);
// both 1602 with ML-KEM-1024, whose key and ciphertext are 1568 bytes each.
const clientHelloSize = (kem) => 1 + 1 + kem.publicKey + 32
const serverHelloSize = (kem) => 1 + 1 + kem.ciphertext + 32

// Finished plaintext: message type, public key, signature.
// 7220 bytes for ML-DSA-87 (1 + 2592 + 4627), 5262 for ML-DSA-65 (1 + 1952 + 3309).
const finishedSize = (set) => 1 + set.publicKey + set.signature

/**
 * Perform handshake as initiator.
 * send(buf)  → Promise<void>   — write one framed message
 * recv(n)    → Promise<Buffer> — read exactly n bytes (stream) or one message (WS)
 * options.identity: optional { publicKey, secretKey }, ML-DSA-87 or ML-DSA-65, for mutual auth
 * options.peerPublicKey: optional ML-DSA-87 or ML-DSA-65 public key the peer must prove
 * options.kem: optional 'ml-kem-1024' (the default) or 'ml-kem-768'
 * Returns { txKey, rxKey } — tx is initiator→responder (C2S), rx is S2C
 * The result also carries peerPublicKey, the key the peer proved, or undefined
 * without mutual auth.
 */
export async function initiatorHandshake(send, recv, options = {}) {
  const ownSet    = identitySet(options.identity)
  const pinnedSet = checkPinnedKeyOption(options)
  const kemSet    = kemSetOf(options.kem)
  const deadline = withDeadline(options.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS)
  try {
    const kem  = generateKemKeypair(kemSet)
    const dh   = generateX25519Keypair()
    const flags = (!ownSet ? 0x00 : FLAG_AUTH | (ownSet === ML_DSA_87 ? FLAG_INITIATOR_87 : 0)) |
      (kemSet === ML_KEM_1024 ? FLAG_KEM_1024 : 0)

    const clientHello = buildClientHello(flags, kem.publicKey, dh.publicKey)
    await deadline.guard(send(clientHello))

    // The ServerHello is in the set this side chose. Its echo of that choice
    // is checked by the signatures over the transcript, as the other echoes are.
    const serverHello = kemSet === ML_KEM_1024
      ? await readServerHello1024(deadline, () => recv(serverHelloSize(kemSet)))
      : await deadline.guard(recv(serverHelloSize(kemSet)))
    validateHello(serverHello, serverHelloSize(kemSet), 'ServerHello',
      FLAG_AUTH | FLAG_INITIATOR_87 | FLAG_RESPONDER_87 | (flags & FLAG_KEM_1024))

    const kemCt       = serverHello.slice(2, 2 + kemSet.ciphertext)
    const serverX25519 = serverHello.slice(2 + kemSet.ciphertext)

    const ssKem = kemDecapsulate(kemCt, kem.secretKey, kemSet)
    const ssDh  = x25519DH(dh.secretKey, serverX25519)
    const salt  = concat(dh.publicKey, serverX25519)
    const { keyC2S, keyS2C } = deriveKeys(ssKem, ssDh, salt, kemSet)

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
    // Read the 1218 bytes of an ML-KEM-768 ClientHello, as 1.4.0 does. A stream
    // hands back exactly that many, so a hello that declares ML-KEM-1024 has 384
    // more to read. A message transport, such as a WebSocket, has already handed
    // back the whole hello, 1218 or 1602 bytes, in one read. Over wrapWebSocket,
    // which says so, a 1218-byte hello that declares ML-KEM-1024 is malformed
    // and its length is refused at once below. Over a caller's own recv the
    // semantics are unknown, so the rest is read as on a stream.
    let clientHello = await deadline.guard(recv(clientHelloSize(ML_KEM_768)))
    if (!options[MESSAGE_TRANSPORT] &&
        clientHello.length === clientHelloSize(ML_KEM_768) && (clientHello[1] & FLAG_KEM_1024)) {
      const rest = await deadline.guard(recv(clientHelloSize(ML_KEM_1024) - clientHelloSize(ML_KEM_768)))
      clientHello = Buffer.concat([clientHello, rest])
    }
    const kemSet = clientHello[1] & FLAG_KEM_1024 ? ML_KEM_1024 : ML_KEM_768
    validateHello(clientHello, clientHelloSize(kemSet), 'ClientHello',
      FLAG_AUTH | FLAG_INITIATOR_87 | FLAG_KEM_1024)

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
    const clientKemEk  = clientHello.slice(2, 2 + kemSet.publicKey)
    const clientX25519 = clientHello.slice(2 + kemSet.publicKey)

    const { ciphertext, sharedSecret: ssKem } = kemEncapsulate(clientKemEk, kemSet)
    const dh  = generateX25519Keypair()
    const ssDh = x25519DH(dh.secretKey, clientX25519)
    const salt = concat(clientX25519, dh.publicKey)
    const { keyC2S, keyS2C } = deriveKeys(ssKem, ssDh, salt, kemSet)

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
  const buf = new Uint8Array(1 + 1 + kemEk.length + 32)
  buf[0] = VERSION
  buf[1] = flags
  buf.set(kemEk,    2)
  buf.set(x25519Pk, 2 + kemEk.length)
  return Buffer.from(buf)
}

function buildServerHello(flags, kemCt, x25519Pk) {
  const buf = new Uint8Array(1 + 1 + kemCt.length + 32)
  buf[0] = VERSION
  buf[1] = flags
  buf.set(kemCt,    2)
  buf.set(x25519Pk, 2 + kemCt.length)
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

// A responder on 1.4.0 or earlier cannot read an ML-KEM-1024 ClientHello. One
// on 1.3.0 or 1.4.0 refuses it and closes the connection without answering. One
// on 1.2.4 or earlier ignores the flag and answers with a 1122-byte ML-KEM-768
// ServerHello, so the wait for the rest of a 1602-byte one runs into the
// deadline. The close or the deadline is all the initiator sees, so while it
// waits for the ServerHello it names the likely cause. It cannot tell an old
// responder from one that failed for another reason, so the original error
// stays on `cause`, and the code is for diagnosis. Nothing falls back to
// ML-KEM-768: a fallback is a downgrade anyone who can cut the connection
// could force, so a caller chooses `kem: 'ml-kem-768'` explicitly.
const CLOSED_AFTER_1024 =
  'the responder closed after an ML-KEM-1024 hello; a responder on kxco-pq-tls 1.4 or earlier ' +
  "cannot read it: upgrade it, or pass kem: 'ml-kem-768'"
const NO_SERVER_HELLO_1024 =
  'no valid ML-KEM-1024 ServerHello before the deadline; likely cause: a responder on kxco-pq-tls 1.2.4 or earlier ' +
  "ignores the ML-KEM-1024 flag, and one on 1.3 or 1.4 refuses it: upgrade the responder, or pass kem: 'ml-kem-768'"

async function readServerHello1024(deadline, read) {
  try {
    return await deadline.guard((async () => read())())
  } catch (cause) {
    const late = cause?.code === ERR_HANDSHAKE_TIMEOUT
    const err = new KxcoPqTlsError(late ? NO_SERVER_HELLO_1024 : CLOSED_AFTER_1024, ERR_RESPONDER_CANNOT_READ_ML_KEM_1024)
    err.cause = cause
    throw err
  }
}

// The ML-KEM set an initiator's `kem` option names. Checked before anything is
// sent, so a misspelt set fails here rather than quietly sending the default.
function kemSetOf(kem) {
  if (kem === undefined) return DEFAULT_KEM
  const set = KEM_SETS.get(kem)
  if (!set)
    throw new KxcoPqTlsError(
      `kem must be 'ml-kem-768' or 'ml-kem-1024', got ${typeof kem === 'string' ? `'${kem}'` : typeof kem}`,
    )
  return set
}

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
