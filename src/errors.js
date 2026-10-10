export class KxcoPqTlsError extends Error {
  /**
   * @param {string} message
   * @param {string} [code] — a stable identifier for failures a caller may want
   *   to branch on. Absent for the general case, because inventing a code per
   *   message would imply a taxonomy this package does not have.
   */
  constructor(message, code) {
    super(message)
    this.name = 'KxcoPqTlsError'
    if (code !== undefined) this.code = code
  }
}

/** The handshake did not complete within its deadline. */
export const ERR_HANDSHAKE_TIMEOUT = 'ERR_KXCO_PQ_TLS_HANDSHAKE_TIMEOUT'

/**
 * An ML-KEM-1024 initiator got no ServerHello it could use: the connection
 * closed, or the deadline passed, before one arrived. The likely cause is a
 * responder on 1.4.0 or earlier. For diagnosis: the original error is `cause`.
 */
export const ERR_RESPONDER_CANNOT_READ_ML_KEM_1024 = 'ERR_KXCO_PQ_TLS_RESPONDER_CANNOT_READ_ML_KEM_1024'
