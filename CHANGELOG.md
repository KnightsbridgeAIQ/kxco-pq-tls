# Changelog

## 1.0.0 — 2026-05-24

Initial release.

### Added
- `wrapStream(socket, options)` — wrap any Node.js Duplex (net.Socket, etc.) with a PQ-TLS channel
- `wrapWebSocket(ws, options)` — wrap a WebSocket (ws package or native API) with a PQ-TLS channel
- Hybrid key exchange: ML-KEM-768 (post-quantum) + X25519 (classical) combined via HKDF
- AES-256-GCM data encryption with per-sequence-number nonces (replay protection)
- Separate encryption keys per direction (C2S / S2C) — cross-channel forgery impossible
- Optional mutual authentication via ML-DSA-65 identity keys (opt-in per connection)
- Cloudflare Workers compatible (pure JS, no native addons, Web Crypto via @noble/ciphers)
- `initiatorHandshake` / `responderHandshake` — low-level API for custom transports
- 20+ tests: crypto primitives, in-memory handshake, TCP stream E2E, tamper detection
