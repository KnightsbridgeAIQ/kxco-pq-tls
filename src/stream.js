import { Duplex } from 'node:stream'
import { initiatorHandshake, responderHandshake } from './handshake.js'
import { sealFrame, openFrame } from './primitives.js'
import { KxcoPqTlsError } from './errors.js'

/**
 * Wrap a Node.js Duplex (net.Socket, etc.) with a PQ-TLS channel.
 * Returns a Promise<Duplex> that resolves once the handshake completes.
 *
 * options.role     — 'initiator' | 'responder'  (required)
 * options.identity — { publicKey, secretKey }    (ML-DSA-65, optional — mutual auth)
 */
export async function wrapStream(socket, options = {}) {
  if (!options.role) throw new KxcoPqTlsError('wrapStream: options.role is required')

  // Handshake messages have fixed known sizes so no framing needed.
  const send = (data) => new Promise((res, rej) =>
    socket.write(Buffer.from(data), (err) => err ? rej(err) : res())
  )
  const recv = (n) => readExactly(socket, n)

  const { txKey, rxKey } =
    options.role === 'initiator'
      ? await initiatorHandshake(send, recv, options)
      : await responderHandshake(send, recv, options)

  return new PqTlsStream(socket, txKey, rxKey)
}

// ---------------------------------------------------------------------------
// Encrypted Duplex stream
// ---------------------------------------------------------------------------

class PqTlsStream extends Duplex {
  constructor(socket, txKey, rxKey) {
    super()
    this._socket = socket
    this._txKey  = txKey
    this._rxKey  = rxKey
    this._txSeq  = 0
    this._rxSeq  = 0
    this._buf    = Buffer.alloc(0)

    socket.on('data',  (chunk) => this._onData(chunk))
    socket.once('end', ()      => this.push(null))
    socket.once('error', (err) => this.destroy(err))
    this.once('finish', ()     => socket.end())
  }

  _write(chunk, _enc, cb) {
    const ct = sealFrame(this._txKey, this._txSeq++, Buffer.from(chunk))
    const hdr = Buffer.allocUnsafe(4)
    hdr.writeUInt32BE(ct.length, 0)
    this._socket.write(Buffer.concat([hdr, ct]), cb)
  }

  _read() {}  // push-based; driven by socket 'data' events

  _onData(chunk) {
    this._buf = Buffer.concat([this._buf, chunk])
    while (this._buf.length >= 4) {
      const frameLen = this._buf.readUInt32BE(0)
      if (this._buf.length < 4 + frameLen) break
      const ct = this._buf.slice(4, 4 + frameLen)
      this._buf = this._buf.slice(4 + frameLen)
      let plain
      try {
        plain = openFrame(this._rxKey, this._rxSeq++, ct)
      } catch (err) {
        this.destroy(err)
        return
      }
      if (!this.push(Buffer.from(plain))) this._socket.pause()
    }
  }
}

// ---------------------------------------------------------------------------
// Stream I/O helpers for handshake
// ---------------------------------------------------------------------------

async function readExactly(socket, n) {
  return new Promise((resolve, reject) => {
    const buf = Buffer.allocUnsafe(n)
    let offset = 0

    const cleanup = () => {
      socket.off('data',  onData)
      socket.off('error', onError)
      socket.off('end',   onEnd)
    }

    const onData = (chunk) => {
      const needed = n - offset
      if (chunk.length <= needed) {
        chunk.copy(buf, offset)
        offset += chunk.length
      } else {
        chunk.copy(buf, offset, 0, needed)
        socket.unshift(chunk.slice(needed))
        offset = n
      }
      if (offset === n) {
        cleanup()
        resolve(buf)
      }
    }

    const onError = (err) => { cleanup(); reject(err) }
    const onEnd   = ()    => { cleanup(); reject(new KxcoPqTlsError('stream ended during handshake')) }

    socket.on('data',  onData)
    socket.once('error', onError)
    socket.once('end',   onEnd)
  })
}
