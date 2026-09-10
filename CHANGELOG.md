# Changelog

## 1.2.2

A handshake that could never complete now fails instead of waiting.

**`handshakeTimeoutMs`, default 30000.** A side configured with an `identity`
sets the auth flag and waits for a `Finished` frame. A peer with no identity of
its own never sends one: it completes the handshake and moves on. Both ends
believe they are correctly configured and the initiator sits there. `recv`
belongs to the caller, so nothing in this package could bound that wait.

It is bounded now, and distinguishable:

```js
import { ERR_HANDSHAKE_TIMEOUT } from 'kxco-pq-tls'
if (err.code === ERR_HANDSHAKE_TIMEOUT) { /* ... */ }
```

The deadline covers the handshake as a whole rather than each message, so a peer
that dribbles bytes cannot hold the connection open by resetting a per-message
timer. `handshakeTimeoutMs: 0` restores the previous unbounded behaviour.

This changes a default. A deployment that relied on an unbounded handshake, for
a peer that legitimately takes more than 30 seconds to answer, needs to set the
option. Nothing else about the handshake, the wire format or the session
changes, and 1.2.1 and 1.2.2 interoperate in both directions.

The signal is narrower than a bare timeout, which is what makes it worth acting
on. It fires only once a peer has accepted the connection and then not sent the
expected frame. A peer speaking a different protocol fails earlier and
differently, on a version byte or a frame length; a peer that was never
reachable fails before the handshake begins, in the caller's socket. In practice
this error means a configuration mismatch, and the message says so.

**ASSESSMENT.md.** Where this package's boundary falls, what cryptographic
agility it has beyond what the primitives provide, and what constrains its
lifecycle. It references the `kxco-post-quantum` evidence rather than restating
it, because a second copy of a conformance claim invites the reader to count it
twice.

**An evidence bundle.** `npm run evidence` records identity, this package's own
tests, its SBOM, registry signature verification, and the `kxco-post-quantum`
version actually installed rather than the range declared.

## 1.2.1

Documentation and a dependency refresh. No source change.

**ASSESSMENT.md.** Where this package's boundary falls, what cryptographic
agility it has beyond what the primitives provide, and what constrains its
lifecycle. It references the `kxco-post-quantum` evidence rather than restating
it, because a second copy of a conformance claim invites the reader to count it
twice.

**`npm run evidence` now exists.** The README already told you to run it and
there was no such script, so the command failed for anyone who followed it.
The bundle records identity, this package's own tests, its SBOM, registry
signature verification, and the `kxco-post-quantum` version actually installed
rather than the range declared.

**`kxco-post-quantum` refreshed to 1.7.2**, from 1.4.0 in the previous
lockfile. Within the existing range, so no declared dependency changed. Tests
pass unchanged.

## 1.2.0

Documentation and positioning. No code change: the handshake, the API and the
wire format are untouched, and all 22 tests pass unchanged.

### New TLS.md

The exact Node, nginx and OpenSSL settings to get `X25519MLKEM768` on the wire
for `relay.kxco.ai` and `chain.kxco.ai`, and — the part that actually matters —
the one command that proves the group was negotiated rather than silently
skipped.

Everything in it was measured on OpenSSL 3.5.6 with Node 26.1.0, not read off a
specification. One measured finding is worth repeating here: **on a Node
server, `groups` is a preference, not a restriction.** A Node server configured
with the PQ group only still accepts a client that offers only X25519, and
completes the handshake on a classical group. The same test against
`openssl s_server -groups X25519MLKEM768` fails the handshake with alert 40. If
you need refusal, terminate TLS in front of Node.

`getEphemeralKeyInfo()` returns `{}` for this group and cannot tell you what
was negotiated. `openssl s_client ... | grep "Negotiated TLS1.3 group"` can.
No output means no hybrid group.

### Repositioned

The README now says, at the top, that **for HTTPS you do not want this
package** — you want TLS with `X25519MLKEM768`, which is standardised, reviewed
by the whole ecosystem, and a configuration change rather than a library.

This package is for what TLS does not cover: mutual ML-DSA-65 identity over a
channel you already have. Two Node processes on a socket that is not HTTP. A
WebSocket where both ends must prove which key they hold rather than which
certificate a CA signed.

The two are complementary: TLS protects the channel, this proves which key is
at the other end of one TLS does not reach.

### Corrected

The Security section claimed all the Noble libraries were "independently
audited by Cure53 (2024)". `@noble/curves` was audited by Trail of Bits
(Feb 2023), Kudelski (Sep 2023) and Cure53 (Sep 2024); `@noble/ciphers` by
Cure53 (Sep 2024); `@noble/post-quantum` is maintainer-audited. Corrected in the README and in
`.socket.yml`. The `quantum-safe` keyword is removed from the manifest.


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
