import { EventEmitter } from 'node:events'
import { initiatorHandshake, responderHandshake, MESSAGE_TRANSPORT } from './handshake.js'
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
 * options.identity: { publicKey, secretKey }, ML-DSA-87 or ML-DSA-65 (optional, mutual auth)
 * options.peerPublicKey: the ML-DSA-87 or ML-DSA-65 public key the peer must prove (optional)
 *
 * The channel's peerPublicKey is the key the peer proved, or undefined without
 * mutual auth.
 */
export async function wrapWebSocket(ws, options = {}) {
  if (!options.role) throw new KxcoPqTlsError('wrapWebSocket: options.role is required')

  // A native WebSocket hands over binary messages as a Blob by default, which
  // cannot be read in order without waiting on each one. Ask for ArrayBuffers.
  // The ws package defaults to Buffers and is left as it is.
  if (ws.binaryType === 'blob') ws.binaryType = 'arraybuffer'

  const inbox = handshakeInbox(ws)
  const send = (data) => wsSend(ws, data)
  const recv = ()     => inbox.next()

  let keys
  try {
    // Each read is one whole message, so the responder can refuse a hello whose
    // length does not match its flags at once, rather than wait for more.
    keys = options.role === 'initiator'
      ? await initiatorHandshake(send, recv, options)
      : await responderHandshake(send, recv, { ...options, [MESSAGE_TRANSPORT]: true })
  } catch (err) {
    // Nothing more can be said on this connection. Closing it tells the peer
    // now, rather than at its own deadline. A peer that ignores the close is
    // then cut off by the WebSocket's own close timeout (30 seconds in the ws
    // package). A WebSocket already closing may refuse to close again, which
    // changes nothing, so the handshake's own error is the one reported.
    try { ws.close() } catch {}
    throw err
  } finally {
    inbox.stop()
  }

  const channel = new PqTlsWebSocket(ws, keys.txKey, keys.rxKey, keys.peerPublicKey)
  // A message can arrive in the same turn as the last handshake message,
  // before the caller has attached a listener to the channel it is about to
  // receive. Hold it until the caller's code after `await wrapWebSocket()` has
  // run, then deliver it, ahead of anything that arrives meanwhile.
  if (inbox.queue.length) channel._deliverLater(inbox.queue)
  return channel
}

// ---------------------------------------------------------------------------
// Encrypted WebSocket wrapper
// ---------------------------------------------------------------------------

export class PqTlsWebSocket extends EventEmitter {
  constructor(ws, txKey, rxKey, peerPublicKey) {
    super()
    this.peerPublicKey = peerPublicKey
    this._ws    = ws
    this._txKey = txKey
    this._rxKey = rxKey
    // A mutual handshake sent its Finished frames as sequence 0 under these
    // keys, so records then start at 1 and no GCM nonce is used twice.
    this._txSeq = peerPublicKey === undefined ? 0 : 1
    this._rxSeq = this._txSeq
    this._held  = null  // messages waiting for _deliverLater, in arrival order

    const onMsg = (data) => {
      if (this._held) this._held.push(data)
      else this._receive(data)
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

  _receive(data) {
    try {
      const plain = openFrame(this._rxKey, this._rxSeq++, toBuffer(data))
      this.emit('message', Buffer.from(plain))
    } catch (err) {
      this.emit('error', err)
    }
  }

  _deliverLater(messages) {
    this._held = messages
    setTimeout(() => {
      const held = this._held
      this._held = null
      for (const data of held) this._receive(data)
    }, 0)
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

// Every message that arrives during the handshake, in order. One listener for
// the whole handshake, because a listener added per read misses a message that
// arrives in the same turn as the one before it, as a responder's ServerHello
// and Finished do. A close or error fails the read waiting now and every read
// after the messages already queued.
function handshakeInbox(ws) {
  const queue = []
  let waiting = null
  let failure = null

  const onMsg = (data) => {
    if (!waiting) { queue.push(data); return }
    const { resolve } = waiting
    waiting = null
    resolve(toBuffer(data))
  }
  const onFail = (err) => {
    failure = err
    if (!waiting) return
    const { reject } = waiting
    waiting = null
    reject(err)
  }
  const onClose     = ()    => onFail(new KxcoPqTlsError('WebSocket closed during handshake'))
  const onError     = (err) => onFail(err)
  const onMsgNative = (e)   => onMsg(e.data)

  const emitter = typeof ws.on === 'function'
  if (emitter) {
    ws.on('message', onMsg)
    ws.on('close',   onClose)
    ws.on('error',   onError)
  } else {
    ws.addEventListener('message', onMsgNative)
    ws.addEventListener('close',   onClose)
    ws.addEventListener('error',   onError)
  }

  return {
    queue,
    next() {
      if (queue.length) return Promise.resolve(toBuffer(queue.shift()))
      if (failure) return Promise.reject(failure)
      return new Promise((resolve, reject) => { waiting = { resolve, reject } })
    },
    stop() {
      if (emitter) {
        ws.off('message', onMsg)
        ws.off('close',   onClose)
        ws.off('error',   onError)
      } else {
        ws.removeEventListener('message', onMsgNative)
        ws.removeEventListener('close',   onClose)
        ws.removeEventListener('error',   onError)
      }
    },
  }
}

function toBuffer(data) {
  if (Buffer.isBuffer(data)) return data
  if (data instanceof Uint8Array) return Buffer.from(data.buffer, data.byteOffset, data.byteLength)
  if (data instanceof ArrayBuffer) return Buffer.from(data)
  return Buffer.from(String(data))
}
