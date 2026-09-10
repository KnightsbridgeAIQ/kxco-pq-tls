# Assessment notes

The answers a buyer's readiness assessment asks for, in one place: what this
package does, how it moves when algorithms move, and what it takes to run it.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs 2,103 NIST ACVP vectors and a cross-implementation interoperability matrix
against OpenSSL 3.5, liboqs, Bouncy Castle and two Python implementations, and
publishes the lot. Cited here, proven there.

## What this package is

A post-quantum secure channel for Node.js streams and WebSockets, with its own
handshake, its own record layer, and mutual ML-DSA-65 identity.

Most of this family computes over bytes a caller hands it. This one carries a
protocol. That is the thing to assess:

**Key exchange is hybrid by construction.** ML-KEM-768 combined with X25519,
mixed through HKDF, with AES-256-GCM and a sequence-number nonce on the records.
Both secrets are always mixed, so the session holds if either primitive holds.
An adversary who breaks X25519 recovers nothing; an adversary who breaks ML-KEM
recovers nothing. This is the belt-and-braces position the standards bodies
recommend for transport, and it is not optional here, which means no deployment
can accidentally end up without it.

**Authentication is mutual and key-based.** With an `identity`, both ends sign
`SHA-256(clientHello || serverHello)` with ML-DSA-65 and exchange the signature
inside the encrypted session. Each side proves which key it holds, not which
certificate some authority was willing to sign. There is no anonymous
connection in that mode and no certificate authority in the path.

**The transcript is covered.** The flags byte lives inside the ClientHello and
the ClientHello is inside the signed transcript, so an active attacker who
flips the mutual-auth bit in flight cannot produce a matching signature. The
downgrade this protocol is most obviously exposed to is closed by construction.

**A handshake completes or it reports.** `handshakeTimeoutMs` bounds the whole
exchange, 30 seconds by default, and fails with
`err.code === 'ERR_KXCO_PQ_TLS_HANDSHAKE_TIMEOUT'`. The deadline is total rather
than per-message, so a peer that dribbles bytes cannot hold a connection open by
resetting a timer. The signal is precise: a peer speaking a different protocol
fails earlier on a version byte or a frame length, and a peer that was never
reachable fails in the caller's socket before this code runs, so this error
means a peer accepted the connection and then did not send the expected frame.
In practice, a configuration mismatch, and the message says so.

**The connection is the caller's; the protocol is ours.** `wrapStream` and
`wrapWebSocket` take an already-connected socket. This package never resolves a
hostname or chooses a peer, which keeps the assessed surface exactly the
handshake, the session keys and the record layer.

## Where it sits

For channels between systems you control on both ends, this is the whole
answer. For a public HTTPS endpoint, terminate TLS 1.3 with the standardised
`X25519MLKEM768` group at the edge; `TLS.md` has the configuration and how to
prove it is on the wire. The two are complementary, and knowing which one a
deployment needs is the point of stating it.

Data at rest is [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault),
long-lived identity keys are
[`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm). A transport holds no
records and keeps no state between sessions, which is why session keys live and
die with the session.

## Agility

**Inherited.** Parameter sets and the two interchangeable backends belong to
`kxco-post-quantum`; see that package's `AGILITY.md`.

**Versioned on the wire.** Both `ClientHello` and `ServerHello` open with
`version = 0x01`, and the HKDF info string is `kxco-pq-tls-v1`. A v2 handshake
is distinguishable on the wire rather than guessed at, and the key schedule of
one version cannot collide with another. That is the mechanism a protocol
migration needs, present before it is needed.

**Migration path.** Deploy responders that accept v1 and v2, move initiators,
retire v1: the add-then-remove staging the primitives package documents in
`MIGRATION.md`, run at the protocol level. Frame sizes are fixed per version
(1184 bytes of ML-KEM-768 encapsulation key and 32 of X25519 in the ClientHello;
1088 and 32 in the ServerHello), which is what makes a version identifiable from
the first byte on the wire.

## Running it

**Release integrity.** Every release carries a SLSA provenance attestation
tying the tarball to the commit and workflow that built it, and a CycloneDX
SBOM as a GitHub Release asset at a permanent unauthenticated URL rather than an
expiring build artifact. `@noble/ciphers`, `@noble/curves` and `@noble/hashes`
are pinned to exact versions, never ranges, so the code performing the symmetric
and classical work cannot change without a release of this package. All three
are checkable without asking us for anything.

**Supported versions.** One line moving forward. Fixes land in the next release.

**Cost.** One ML-KEM-768 encapsulation and one X25519 exchange per connection,
plus two ML-DSA-65 operations per side with mutual authentication on. Record
throughput afterwards is AES-256-GCM and is not the constraint. Connection reuse
is the lever for designs that open many short connections, and the primitives
package's `BENCHMARKS.md` has the per-operation figures at p50 and p99 on both
backends.

**Sizing.** A ClientHello is 1218 bytes and a ServerHello 1122. Worth knowing
for constrained links, and the reason the sizes are documented rather than
discovered.

**Runtime.** Node 20.19 and later. Node 24 and later run the primitives in
OpenSSL 3.5 and are roughly 4x to 8x faster per operation; everything works on
either, with identical wire bytes.

## Correcting this document

Every claim here is checkable against `src/`, the test suite and `TLS.md`. If
one does not match, that is a defect worth reporting through the repository's
issues.
