import { mlKem, mlDsa } from 'kxco-post-quantum'
import { x25519 } from '@noble/curves/ed25519'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/ciphers/webcrypto'
import { KxcoPqTlsError } from './errors.js'

const PROTOCOL = new TextEncoder().encode('kxco-pq-tls-v1')
const INFO_C2S  = new TextEncoder().encode('kxco-pq-tls-v1-c2s')
const INFO_S2C  = new TextEncoder().encode('kxco-pq-tls-v1-s2c')

export function generateKemKeypair() {
  return mlKem.ml_kem768.keygen()
}

export function generateX25519Keypair() {
  const secretKey = x25519.utils.randomPrivateKey()
  const publicKey = x25519.getPublicKey(secretKey)
  return { publicKey, secretKey }
}

export function kemEncapsulate(publicKey) {
  const { cipherText, sharedSecret } = mlKem.ml_kem768.encapsulate(publicKey)
  return { ciphertext: new Uint8Array(cipherText), sharedSecret: new Uint8Array(sharedSecret) }
}

export function kemDecapsulate(ciphertext, secretKey) {
  return mlKem.ml_kem768.decapsulate(new Uint8Array(ciphertext), new Uint8Array(secretKey))
}

export function x25519DH(sk, pk) {
  return x25519.getSharedSecret(sk, pk)  // Uint8Array(32)
}

// Derive per-direction session keys from the two shared secrets.
// salt = initiator_x25519_pk || responder_x25519_pk (64 bytes, transcript-bound)
export function deriveKeys(ssKem, ssDh, salt) {
  const ikm = new Uint8Array(64)
  ikm.set(ssKem)
  ikm.set(ssDh, 32)
  const base = hkdf(sha256, ikm, salt, PROTOCOL, 32)
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

// ML-DSA-65 identity helpers for mutual auth
export function dsaSign(secretKey, message) {
  return mlDsa.ml_dsa65.sign(new Uint8Array(secretKey), message)
}

export function dsaVerify(publicKey, message, signature) {
  return mlDsa.ml_dsa65.verify(new Uint8Array(publicKey), message, new Uint8Array(signature))
}

export { randomBytes, sha256 }
