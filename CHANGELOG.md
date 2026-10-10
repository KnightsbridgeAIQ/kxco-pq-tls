# Changelog

## 1.5.0 (2026-10-10)

**ML-KEM-1024 for the session key, when the initiator asks for it.** An
initiator given `kem: 'ml-kem-1024'` combines ML-KEM-1024 (NIST FIPS 203,
security category 5) with X25519. It declares the set in bit 3 of its
ClientHello, and both hellos are 1602 bytes. The session key takes its own HKDF
label, `kxco-pq-tls-v1-ml-kem-1024`. The default stays ML-KEM-768.

**A responder accepts both sets** and answers in the one the initiator chose,
echoing bit 3 in its ServerHello. On a stream it reads the 1218-byte hello as
before and reads the other 384 bytes only when bit 3 is set. Over a WebSocket,
or any transport that hands over a whole message per read, it takes a 1218 or
1602-byte hello by its flag. Both hellos are inside the transcript each side
signs, so with mutual authentication a bit 3 changed in flight fails the
Finished check.

**Without `kem: 'ml-kem-1024'` nothing changes on the wire.** Every message,
flag and key label is what 1.4.0 sends and derives, so 1.5.0 and 1.4.0
interoperate in both roles. A responder on 1.4.0 or earlier cannot read an
ML-KEM-1024 hello, so upgrade responders first. The README has a version
compatibility table.

A `kem` value other than `'ml-kem-768'` or `'ml-kem-1024'` is refused with
`KxcoPqTlsError` before anything is sent. The typings add `kem` to
`ChannelOptions` and `HandshakeOptions`.

The tests run the handshake against kxco-pq-tls 1.4.0 from npm over TCP, over
WebSockets, and through the handshake functions on a transport of their own.

## 1.4.0 (2026-10-09)

Runtime support. No change to the API or its behaviour.

**Node.js 22.12 or later is required.** `engines.node` moves from `>=20.19`
to `>=22.12`. Node 20 reached end of life on 30 April 2026. 22.12 is the
first Node 22 release that loads ES modules through `require()` without a
flag, the same property the 20.19 floor provided.

**CI tests every change on Node 22, 24 and 26.** It tested Node 20, 22 and 24 before.

**Releases are built on Node 26**, where they were built on Node 22.
Node 26 ships npm 11.20, which already carries Trusted Publishing, so the
release job no longer downloads npm 11 separately.

## 1.3.0 (2026-10-07)

**ML-DSA-87 identities.** Mutual authentication takes an ML-DSA-87 or an
ML-DSA-65 keypair (NIST FIPS 204), and ML-DSA-87 is the recommended set for new
identities. Each side's public key sets its parameter set: 2592 bytes is
ML-DSA-87 and 1952 bytes is ML-DSA-65. The two sides may use different sets, so
a server can move to ML-DSA-87 while its clients still hold ML-DSA-65 keys, and
the reverse. `peerPublicKey` takes a key of either set.

Each side declares its set in a flag of the hello it sends: bit 1 of the
ClientHello for the initiator, bit 2 of the ServerHello for the responder. The
peer reads the Finished frame at the declared size, 7236 bytes on the wire for
ML-DSA-87 and 5278 for ML-DSA-65. Both hellos are inside the transcript each
side signs, so each signature covers the set each side declared. A Finished
frame of the wrong size for its sender's declared set is refused. A pinned
`peerPublicKey` fixes the set the peer must declare, and a peer that declares
the other set is refused before this side signs.

An identity or `peerPublicKey` of any other length is refused with
`KxcoPqTlsError` before anything is sent, as is an identity whose secret key is
the wrong length for its public key's set. A hello carrying a flag this version
does not know is refused.

With ML-DSA-65 at both ends the set flags are clear, and every message has the
layout and flags 1.2.4 sends: 1.3.0 and 1.2.4 interoperate in both roles, with
ML-DSA-65 identities and without identities. ML-DSA-87 on either side needs
1.3.0 at both ends.

## 1.2.4

Mutual authentication completes over TCP sockets and WebSockets. The stream
reader keeps a handshake message that arrives together with the next one, and
`wrapWebSocket` keeps every message that arrives during the handshake.

The channel exposes `peerPublicKey`, the ML-DSA-65 key the peer proved, or
`undefined` without mutual authentication, and the `peerPublicKey` option pins
the key the peer must prove. A responder holding an identity refuses an
initiator that does not request mutual authentication.

Each side's Finished signature names the side that signs. After mutual
authentication, records start at sequence 1, because the Finished frames use
sequence 0 under the same keys.

A failed handshake closes the connection: `wrapStream` destroys the socket and
`wrapWebSocket` closes the WebSocket. `wrapWebSocket` switches a native
WebSocket's `binaryType` from `'blob'` to `'arraybuffer'`. The encrypted stream
resumes its socket when read, so `pipe()`, `for await` and large messages
deliver everything.

Sessions without identities are unchanged on the wire and interoperate with
1.2.3. Mutual authentication needs 1.2.4 at both ends.

**The npm page leads with what the package proves.** The first screen now says why a
recorded session is what a harvest-now-decrypt-later adversary keeps, in the
words of Executive Order 14412, how the hybrid key exchange closes it, the
evidence underneath it and the migration dates set by NIST, Executive Order
14412, OMB M-26-15 and the UK NCSC.

A family table maps every KXCO package to the job it does, and a new For
institutions section sets out the operated services and how to reach us. The
evidence documents are unchanged and linked from the page.

The stream and WebSocket quick starts now show a message and its reply, and the
mutual authentication example is one file with both ends.

Every GitHub Action in CI is now pinned by commit SHA, as the page states.

A NOTICE file names the copyright owner, Knightsbridge Financial Ltd, trading
as KXCO, and ships in the package, so anyone who redistributes it carries the
attribution, as section 4(d) of the Apache License requires.

## 1.2.3

The handshake deadline added in 1.2.2 could not fire.

Its timer was `unref`'d, so it could not hold the event loop open. In a process
where the handshake is the only pending work, the loop drains and the timer
never runs: the deadline silently does nothing, which is the exact hang it was
written to prevent. The option was accepted, documented and inert.

It surfaced as four failing tests on Node 20 and 22, where the runner reported
that promise resolution was still pending while the event loop had already
resolved. Node 24 masked it. That is why **1.2.2 was tagged but never published
to npm**: its release build failed on `npm test` and the version does not exist
on the registry. Upgrade from 1.2.1 straight to 1.2.3.

Holding the loop open is bounded. Both handshakes clear the timer in a `finally`
block, so it lives no longer than the handshake does.

CI now reports a failing assertion as a workflow annotation rather than only in
the run log, because downloading a run log needs admin rights on the repository
and the failure was visible but unreadable without them.

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
