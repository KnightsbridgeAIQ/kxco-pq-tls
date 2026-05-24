/**
 * kxco-pq-tls handshake protocol v1
 *
 * ClientHello (1218 bytes):
 *   [1]    version = 0x01
 *   [1]    flags   (bit 0 = mutual_auth_requested)
 *   [1184] ML-KEM-768 ephemeral encap key
 *   [32]   X25519 ephemeral public key
 *
 * ServerHello (1122 bytes):
 *   [1]    version = 0x01
 *   [1]    flags
 *   [1088] ML-KEM-768 ciphertext
 *   [32]   X25519 ephemeral public key
 *
 * Session keys: HKDF(ss_kem || ss_dh, salt=c_x25519_pk||s_x25519_pk, info="kxco-pq-tls-v1")
 * then split into keyC2S and keyS2C.
 *
 * If mutual auth requested, after key establishment both sides exchange a
 * Finished frame (sent encrypted over the new session) containing their
 * ML-DSA-65 identity public key and a signature over SHA-256(clientHello||serverHello).
 *
 * Finished plaintext (5262 bytes):
 *   [1]    msg_type = 0x01
 *   [1952] ML-DSA-65 public key
 *   [3309] ML-DSA-65 signature over SHA-256(clientHello || serverHello)
 */

import {
  generateKemKeypair, generateX25519Keypair,
  kemEncapsulate, kemDecapsulate, x25519DH,
  deriveKeys, sealFrame, openFrame,
  dsaSign, dsaVerify, sha256,
} from './primitives.js'
import { KxcoPqTlsError } from './errors.js'

const VERSION      = 0x01
const FLAG_AUTH    = 0x01
const MSG_FINISHED = 0x01

const CLIENT_HELLO_SIZE = 1218   // 1 + 1 + 1184 + 32
const SERVER_HELLO_SIZE = 1122   // 1 + 1 + 1088 + 32
const FINISHED_SIZE     = 5262   // 1 + 1952 + 3309

/**
 * Perform handshake as initiator.
 * send(buf)  → Promise<void>   — write one framed message
 * recv(n)    → Promise<Buffer> — read exactly n bytes (stream) or one message (WS)
 * options.identity → optional { publicKey, secretKey } (ML-DSA-65) for mutual auth
 * Returns { txKey, rxKey } — tx is initiator→responder (C2S), rx is S2C
 */
export async function initiatorHandshake(send, recv, options = {}) {
  const kem  = generateKemKeypair()
  const dh   = generateX25519Keypair()
  const flags = options.identity ? FLAG_AUTH : 0x00

  const clientHello = buildClientHello(flags, kem.publicKey, dh.publicKey)
  await send(clientHello)

  const serverHello = await recv(SERVER_HELLO_SIZE)
  validateHello(serverHello, SERVER_HELLO_SIZE, 'ServerHello')

  const kemCt       = serverHello.slice(2, 2 + 1088)
  const serverX25519 = serverHello.slice(2 + 1088)

  const ssKem = kemDecapsulate(kemCt, kem.secretKey)
  const ssDh  = x25519DH(dh.secretKey, serverX25519)
  const salt  = concat(dh.publicKey, serverX25519)
  const { keyC2S, keyS2C } = deriveKeys(ssKem, ssDh, salt)

  if (options.identity) {
    const transcript = sha256.create()
      .update(clientHello).update(serverHello).digest()
    await exchangeFinished(send, recv, keyC2S, keyS2C, options.identity, transcript, 'initiator')
  }

  return { txKey: keyC2S, rxKey: keyS2C }
}

/**
 * Perform handshake as responder.
 * Returns { txKey, rxKey } — tx is responder→initiator (S2C), rx is C2S
 */
export async function responderHandshake(send, recv, options = {}) {
  const clientHello = await recv(CLIENT_HELLO_SIZE)
  validateHello(clientHello, CLIENT_HELLO_SIZE, 'ClientHello')

  const flags        = clientHello[1]
  const clientKemEk  = clientHello.slice(2, 2 + 1184)
  const clientX25519 = clientHello.slice(2 + 1184)

  const { ciphertext, sharedSecret: ssKem } = kemEncapsulate(clientKemEk)
  const dh  = generateX25519Keypair()
  const ssDh = x25519DH(dh.secretKey, clientX25519)
  const salt = concat(clientX25519, dh.publicKey)
  const { keyC2S, keyS2C } = deriveKeys(ssKem, ssDh, salt)

  const serverHello = buildServerHello(flags, ciphertext, dh.publicKey)
  await send(serverHello)

  if ((flags & FLAG_AUTH) && options.identity) {
    const transcript = sha256.create()
      .update(clientHello).update(serverHello).digest()
    await exchangeFinished(send, recv, keyS2C, keyC2S, options.identity, transcript, 'responder')
  }

  return { txKey: keyS2C, rxKey: keyC2S }
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

function validateHello(buf, expectedLen, name) {
  if (buf.length !== expectedLen)
    throw new KxcoPqTlsError(`${name}: expected ${expectedLen} bytes, got ${buf.length}`)
  if (buf[0] !== VERSION)
    throw new KxcoPqTlsError(`${name}: unsupported version 0x${buf[0].toString(16)}`)
}

async function exchangeFinished(send, recv, txKey, rxKey, identity, transcript, role) {
  // Send our Finished first, then receive theirs.
  // The encrypted sequence starts at 0 for each direction.
  const sig      = dsaSign(identity.secretKey, transcript)
  const finished = buildFinished(identity.publicKey, sig)
  await send(sealFrame(txKey, 0, finished))

  const rxBuf     = await recv(FINISHED_SIZE + 16)  // +16 GCM tag
  const plaintext = openFrame(rxKey, 0, Buffer.from(rxBuf))
  verifyFinished(plaintext, transcript, role)
}

function buildFinished(identityPk, sig) {
  const buf = new Uint8Array(FINISHED_SIZE)
  buf[0] = MSG_FINISHED
  buf.set(identityPk, 1)
  buf.set(sig, 1 + 1952)
  return buf
}

function verifyFinished(plaintext, transcript, role) {
  if (plaintext[0] !== MSG_FINISHED)
    throw new KxcoPqTlsError('unexpected finished message type')
  const identityPk = plaintext.slice(1, 1 + 1952)
  const sig        = plaintext.slice(1 + 1952)
  if (!dsaVerify(identityPk, transcript, sig))
    throw new KxcoPqTlsError(`${role}: peer identity verification failed`)
}

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) { out.set(a, off); off += a.length }
  return out
}
