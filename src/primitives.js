import { mlKem, mlKem1024, mlDsa, mlDsa87 } from 'kxco-post-quantum'
import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { gcm } from '@noble/ciphers/aes.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { KxcoPqTlsError } from './errors.js'

const PROTOCOL = new TextEncoder().encode('kxco-pq-tls-v1')
const INFO_C2S  = new TextEncoder().encode('kxco-pq-tls-v1-c2s')
const INFO_S2C  = new TextEncoder().encode('kxco-pq-tls-v1-s2c')

// The ML-KEM parameter sets a session may use (FIPS 203), with their sizes in
// bytes. The initiator chooses, and a ClientHello flag declares ML-KEM-1024.
// Each set has its own label for the session key, so the two key schedules
// never meet. The ML-KEM-768 label is the one 1.4.0 uses.
export const ML_KEM_768 = Object.freeze({
  name: 'ML-KEM-768', publicKey: 1184, ciphertext: 1088, impl: mlKem,
  keygen: () => mlKem.ml_kem768.keygen(), label: PROTOCOL,
})
export const ML_KEM_1024 = Object.freeze({
  name: 'ML-KEM-1024', publicKey: 1568, ciphertext: 1568, impl: mlKem1024,
  keygen: () => mlKem1024.ml_kem1024.keygen(),
  label: new TextEncoder().encode('kxco-pq-tls-v1-ml-kem-1024'),
})

export function generateKemKeypair(set = ML_KEM_768) {
  return set.keygen()
}

export function generateX25519Keypair() {
  const secretKey = x25519.utils.randomSecretKey()
  const publicKey = x25519.getPublicKey(secretKey)
  return { publicKey, secretKey }
}

export function kemEncapsulate(publicKey, set = ML_KEM_768) {
  const { ciphertext, sharedSecret } = set.impl.encapsulate(new Uint8Array(publicKey))
  return { ciphertext: new Uint8Array(ciphertext), sharedSecret: new Uint8Array(sharedSecret) }
}

export function kemDecapsulate(ciphertext, secretKey, set = ML_KEM_768) {
  return new Uint8Array(set.impl.decapsulate(new Uint8Array(ciphertext), new Uint8Array(secretKey)))
}

export function x25519DH(sk, pk) {
  return x25519.getSharedSecret(sk, pk)  // Uint8Array(32)
}

// Derive per-direction session keys from the two shared secrets.
// salt = initiator_x25519_pk || responder_x25519_pk (64 bytes, transcript-bound)
// The label is the ML-KEM set's: "kxco-pq-tls-v1" for ML-KEM-768, as in 1.4.0.
export function deriveKeys(ssKem, ssDh, salt, set = ML_KEM_768) {
  const ikm = new Uint8Array(64)
  ikm.set(ssKem)
  ikm.set(ssDh, 32)
  const base = hkdf(sha256, ikm, salt, set.label, 32)
  return {
    keyC2S: hkdf(sha256, base, new Uint8Array(0), INFO_C2S, 32),
    keyS2C: hkdf(sha256, base, new Uint8Array(0), INFO_S2C, 32),
  }
}

// Returns ciphertext with 16-byte GCM tag appended.
export function sealFrame(key, seq, plaintext) {
  const nonce = seqNonce(seq)
  return gcm(key, nonce).encrypt(plaintext)
}

// Throws KxcoPqTlsError on authentication failure.
export function openFrame(key, seq, ciphertext) {
  try {
    return gcm(key, seqNonce(seq)).decrypt(ciphertext)
  } catch {
    throw new KxcoPqTlsError('frame authentication failed')
  }
}

function seqNonce(seq) {
  const nonce = new Uint8Array(12)
  const v = new DataView(nonce.buffer)
  // 64-bit big-endian sequence number in bytes 0–7; bytes 8–11 remain zero
  v.setUint32(0, Math.floor(seq / 0x100000000) >>> 0, false)
  v.setUint32(4, seq >>> 0, false)
  return nonce
}

// The ML-DSA parameter sets an identity may sign with (FIPS 204), with their
// sizes in bytes. A public key's length names its set, and these are the only
// lengths accepted.
export const ML_DSA_87 = Object.freeze({
  name: 'ML-DSA-87', publicKey: 2592, secretKey: 4896, signature: 4627, impl: mlDsa87,
})
export const ML_DSA_65 = Object.freeze({
  name: 'ML-DSA-65', publicKey: 1952, secretKey: 4032, signature: 3309, impl: mlDsa,
})

/** The parameter set a public key belongs to, or undefined for any other length. */
export function dsaSetOf(publicKey) {
  if (!(publicKey instanceof Uint8Array)) return undefined
  if (publicKey.length === ML_DSA_87.publicKey) return ML_DSA_87
  if (publicKey.length === ML_DSA_65.publicKey) return ML_DSA_65
  return undefined
}

// ML-DSA identity helpers for mutual auth
// Wire format embeds this signature at a fixed byte offset (see finishedSize
// in handshake.js), so it stays raw bytes: the wrapper's hex return is
// converted back to bytes rather than changing the on-the-wire shape.
export function dsaSign(set, secretKey, message) {
  return Buffer.from(set.impl.sign(new Uint8Array(secretKey), message), 'hex')
}

export function dsaVerify(set, publicKey, message, signature) {
  return set.impl.verify(new Uint8Array(publicKey), message, Buffer.from(signature).toString('hex'))
}

export { randomBytes, sha256 }
