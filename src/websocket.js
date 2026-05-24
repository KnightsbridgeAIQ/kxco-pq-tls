import { EventEmitter } from 'node:events'
import { initiatorHandshake, responderHandshake } from './handshake.js'
import { sealFrame, openFrame } from './primitives.js'
import { KxcoPqTlsError } from './errors.js'

/**
 * Wrap a WebSocket with a PQ-TLS channel.
 * Compatible with the `ws` npm package (Node.js) and the native WebSocket API
 * (Cloudflare Workers, browsers, Node.js 22+).
 *
 * Returns a Promise<PqTlsWebSocket> that resolves once the handshake completes.
 *
 * options.role     — 'initiator' | 'responder'  (required)
 * options.identity — { publicKey, secretKey }    (ML-DSA-65, optional — mutual auth)
 */
export async function wrapWebSocket(ws, options = {}) {
  if (!options.role) throw new KxcoPqTlsError('wrapWebSocket: options.role is required')

  const send = (data) => wsSend(ws, data)
  const recv = ()     => wsRecv(ws)

  const { txKey, rxKey } =
    options.role === 'initiator'
      ? await initiatorHandshake(send, recv, options)
      : await responderHandshake(send, recv, options)

  return new PqTlsWebSocket(ws, txKey, rxKey)
}

// ---------------------------------------------------------------------------
// Encrypted WebSocket wrapper
// ---------------------------------------------------------------------------

export class PqTlsWebSocket extends EventEmitter {
  constructor(ws, txKey, rxKey) {
    super()
    this._ws    = ws
    this._txKey = txKey
    this._rxKey = rxKey
    this._txSeq = 0
    this._rxSeq = 0

    const onMsg = (data) => {
      try {
        const plain = openFrame(this._rxKey, this._rxSeq++, toBuffer(data))
        this.emit('message', Buffer.from(plain))
      } catch (err) {
        this.emit('error', err)
      }
    }

    const onClose  = (code, reason) => this.emit('close', code, reason)
    const onError  = (err)          => this.emit('error', err)

    // Support both ws (Node.js) and native WebSocket (Workers/browser) event APIs
    if (typeof ws.on === 'function') {
      ws.on('message', onMsg)
      ws.on('close',   onClose)
      ws.on('error',   onError)
    } else {
      ws.addEventListener('message', (e) => onMsg(e.data))
      ws.addEventListener('close',   (e) => this.emit('close', e.code, e.reason))
      ws.addEventListener('error',   (e) => this.emit('error', e))
    }
  }

  send(data) {
    const ct = sealFrame(this._txKey, this._txSeq++, toBuffer(data))
    wsSend(this._ws, ct)
  }

  close(code, reason) { this._ws.close(code, reason) }
}

// ---------------------------------------------------------------------------
// WebSocket helpers
// ---------------------------------------------------------------------------

function wsSend(ws, data) {
  return new Promise((resolve, reject) => {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data)
    if (typeof ws.send === 'function') {
      // ws package: send(data, callback)
      try {
        const result = ws.send(buf, (err) => err ? reject(err) : resolve())
        // Native WebSocket (Workers/browser) returns undefined and has no callback
        if (result === undefined && typeof ws.readyState !== 'undefined') resolve()
      } catch (err) {
        reject(err)
      }
    } else {
      reject(new KxcoPqTlsError('ws.send is not a function'))
    }
  })
}

function wsRecv(ws) {
  return new Promise((resolve, reject) => {
    const onMsg   = (data)  => { cleanup(); resolve(toBuffer(data)) }
    const onClose = ()      => { cleanup(); reject(new KxcoPqTlsError('WebSocket closed during handshake')) }
    const onError = (err)   => { cleanup(); reject(err) }

    const cleanup = () => {
      if (typeof ws.off === 'function') {
        ws.off('message', onMsg)
        ws.off('close',   onClose)
        ws.off('error',   onError)
      } else {
        ws.removeEventListener('message', onMsgNative)
        ws.removeEventListener('close',   onClose)
        ws.removeEventListener('error',   onError)
      }
    }

    const onMsgNative = (e) => onMsg(e.data)

    if (typeof ws.once === 'function') {
      ws.once('message', onMsg)
      ws.once('close',   onClose)
      ws.once('error',   onError)
    } else {
      ws.addEventListener('message', onMsgNative, { once: true })
      ws.addEventListener('close',   onClose,     { once: true })
      ws.addEventListener('error',   onError,     { once: true })
    }
  })
}

function toBuffer(data) {
  if (Buffer.isBuffer(data)) return data
  if (data instanceof Uint8Array) return Buffer.from(data.buffer, data.byteOffset, data.byteLength)
  if (data instanceof ArrayBuffer) return Buffer.from(data)
  return Buffer.from(String(data))
}
