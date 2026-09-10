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
