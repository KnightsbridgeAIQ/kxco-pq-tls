import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKemKeypair, generateX25519Keypair,
  kemEncapsulate, kemDecapsulate, x25519DH,
  deriveKeys, sealFrame, openFrame,
  ML_KEM_768, ML_KEM_1024,
} from '../src/primitives.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

test('ML-KEM-768 encap/decap roundtrip', () => {
  const kp = generateKemKeypair()
  assert.equal(kp.publicKey.length, 1184)
  assert.equal(kp.secretKey.length, 2400)

  const { ciphertext, sharedSecret: ss1 } = kemEncapsulate(kp.publicKey)
  assert.equal(ciphertext.length, 1088)
  assert.equal(ss1.length, 32)

  const ss2 = kemDecapsulate(ciphertext, kp.secretKey)
  assert.deepEqual(ss2, ss1)
})

test('X25519 key exchange produces equal shared secrets', () => {
  const alice = generateX25519Keypair()
  const bob   = generateX25519Keypair()
  assert.equal(alice.publicKey.length, 32)

  const ss1 = x25519DH(alice.secretKey, bob.publicKey)
  const ss2 = x25519DH(bob.secretKey, alice.publicKey)
  assert.deepEqual(ss1, ss2)
})

test('different X25519 keypairs produce different secrets', () => {
  const alice  = generateX25519Keypair()
  const bob    = generateX25519Keypair()
  const carol  = generateX25519Keypair()
  const ss1 = x25519DH(alice.secretKey, bob.publicKey)
  const ss2 = x25519DH(alice.secretKey, carol.publicKey)
  assert.notDeepEqual(ss1, ss2)
})

test('deriveKeys produces 32-byte keys', () => {
  const ssKem = new Uint8Array(32).fill(1)
  const ssDh  = new Uint8Array(32).fill(2)
  const salt  = new Uint8Array(64).fill(3)
  const { keyC2S, keyS2C } = deriveKeys(ssKem, ssDh, salt)
  assert.equal(keyC2S.length, 32)
  assert.equal(keyS2C.length, 32)
  assert.notDeepEqual(keyC2S, keyS2C)
})

test('deriveKeys is deterministic', () => {
  const ssKem = new Uint8Array(32).fill(5)
  const ssDh  = new Uint8Array(32).fill(6)
  const salt  = new Uint8Array(64).fill(7)
  const a = deriveKeys(ssKem, ssDh, salt)
  const b = deriveKeys(ssKem, ssDh, salt)
  assert.deepEqual(a.keyC2S, b.keyC2S)
  assert.deepEqual(a.keyS2C, b.keyS2C)
})

test('sealFrame / openFrame roundtrip', () => {
  const key  = new Uint8Array(32).fill(0xab)
  const data = Buffer.from('hello post-quantum world')
  const ct   = sealFrame(key, 0, data)
  const pt   = openFrame(key, 0, ct)
  assert.deepEqual(Buffer.from(pt), data)
})

test('openFrame rejects wrong sequence number', () => {
  const key = new Uint8Array(32).fill(0xcd)
  const ct  = sealFrame(key, 0, Buffer.from('secret'))
  assert.throws(() => openFrame(key, 1, ct), /authentication failed/)
})

test('openFrame rejects tampered ciphertext', () => {
  const key = new Uint8Array(32).fill(0xef)
  const ct  = Buffer.from(sealFrame(key, 0, Buffer.from('data')))
  ct[0] ^= 0xff
  assert.throws(() => openFrame(key, 0, ct), /authentication failed/)
})

test('sealFrame with large payload', () => {
  const key  = new Uint8Array(32).fill(0x11)
  const data = Buffer.alloc(64 * 1024, 0x42)
  const ct   = sealFrame(key, 99, data)
  const pt   = openFrame(key, 99, ct)
  assert.deepEqual(Buffer.from(pt), data)
})

test('sequence numbers are independent per key', () => {
  const k1 = new Uint8Array(32).fill(1)
  const k2 = new Uint8Array(32).fill(2)
  const ct1 = sealFrame(k1, 0, Buffer.from('a'))
  const ct2 = sealFrame(k2, 0, Buffer.from('b'))
  // Cross-key decryption must fail
  assert.throws(() => openFrame(k2, 0, ct1), /authentication failed/)
  assert.throws(() => openFrame(k1, 0, ct2), /authentication failed/)
})

test('ML-KEM-1024 encap/decap roundtrip', () => {
  const kp = generateKemKeypair(ML_KEM_1024)
  assert.equal(kp.publicKey.length, 1568)
  assert.equal(kp.secretKey.length, 3168)

  const { ciphertext, sharedSecret: ss1 } = kemEncapsulate(kp.publicKey, ML_KEM_1024)
  assert.equal(ciphertext.length, 1568)
  assert.equal(ss1.length, 32)

  assert.deepEqual(kemDecapsulate(ciphertext, kp.secretKey, ML_KEM_1024), ss1)
})

test('deriveKeys labels each ML-KEM set: kxco-pq-tls-v1 for ML-KEM-768, as 1.4.0, and kxco-pq-tls-v1-ml-kem-1024', () => {
  const ssKem = new Uint8Array(32).fill(8)
  const ssDh  = new Uint8Array(32).fill(9)
  const salt  = new Uint8Array(64).fill(10)
  const expected = (label) => {
    const ikm = new Uint8Array(64)
    ikm.set(ssKem)
    ikm.set(ssDh, 32)
    const base = hkdf(sha256, ikm, salt, new TextEncoder().encode(label), 32)
    const split = (info) => hkdf(sha256, base, new Uint8Array(0), new TextEncoder().encode(info), 32)
    return { keyC2S: split('kxco-pq-tls-v1-c2s'), keyS2C: split('kxco-pq-tls-v1-s2c') }
  }
  assert.deepEqual(deriveKeys(ssKem, ssDh, salt), expected('kxco-pq-tls-v1'))
  assert.deepEqual(deriveKeys(ssKem, ssDh, salt, ML_KEM_768), expected('kxco-pq-tls-v1'))
  assert.deepEqual(deriveKeys(ssKem, ssDh, salt, ML_KEM_1024), expected('kxco-pq-tls-v1-ml-kem-1024'))
  assert.notDeepEqual(deriveKeys(ssKem, ssDh, salt, ML_KEM_1024), deriveKeys(ssKem, ssDh, salt))
})
