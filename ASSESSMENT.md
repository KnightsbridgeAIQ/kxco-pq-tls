# Assessment notes

What a buyer assessing this package needs that the README does not tell them:
where the product boundary falls, what cryptographic agility it has, and what
constrains its lifecycle.

This package does not implement ML-KEM, ML-DSA or SLH-DSA. It calls
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs the NIST ACVP vectors and the cross-implementation interoperability matrix
and publishes them in its own evidence bundle. Those numbers are evidence about
that package. They say the primitives are correct; they say nothing about the
protocol built here, and this document is about the protocol.

## Boundary

**What the assessed thing is, and this one is different from its siblings.**
Most packages in this family are libraries that compute over bytes the caller
supplies. This one carries its own wire protocol and it moves data over a
socket the caller owns. `src/handshake.js`, `src/stream.js` and
`src/websocket.js` are all in the assessed surface.

**Operate: the connection is the caller's, the protocol is ours.** `wrapStream`
and `wrapWebSocket` take an already-connected socket. This package never
resolves a hostname, opens a connection or chooses a peer. What it does own is
everything after that: the handshake, the session keys and the record layer. So
the network boundary is exact. Transport establishment is outside; transport
confidentiality is inside.

**Operate: what the handshake actually is.** ML-KEM-768 combined with X25519,
mixed through HKDF, with AES-256-GCM and a sequence-number nonce for records.
Mutual authentication is optional and adds an ML-DSA-65 signature over
`SHA-256(clientHello || serverHello)`.

Two things follow that a buyer should have stated rather than inferred:

- *It is hybrid by construction and cannot be run PQ-only.* Both secrets are
  always mixed. An adversary breaking X25519 does not recover the session key,
  which is the point, and it also means a classical primitive is on the path by
  design. Under a policy that forbids classical key agreement outright, this
  does not comply, and no flag makes it comply.
- *Authentication is off unless asked for.* Without `mutual_auth_requested`,
  the handshake is unauthenticated and therefore open to an active
  machine-in-the-middle. It is encrypted, not authenticated. That is a
  reasonable default only where the caller has already authenticated the peer
  by other means.

**A configuration mismatch stalls rather than reporting.** The two sides gate
authentication differently. The initiator runs the `Finished` exchange whenever
it has an `identity`; the responder runs it only when the client set the flag
*and* the responder itself has an `identity`. So an initiator configured for
mutual authentication against a responder that has no identity will wait for a
`Finished` frame that is never sent.

It does not downgrade. The flags byte is inside the ClientHello and the
ClientHello is inside the signed transcript, so an attacker who clears the bit
in transit cannot produce a valid signature; what they get is the same stall.

**Bounded since 1.2.2.** `handshakeTimeoutMs` defaults to 30 seconds and fails
with `err.code === 'ERR_KXCO_PQ_TLS_HANDSHAKE_TIMEOUT'`, so the mismatch is now
a diagnosable error rather than a hang. The deadline covers the handshake as a
whole, not each message, so a peer that dribbles bytes cannot extend it. Pass
`0` for the previous unbounded behaviour.

What it still cannot do is tell you *which* of the causes applies: an
unreachable peer, a peer not speaking this protocol, and a peer configured
without an identity all present as the same timeout. The error message names
all three rather than guessing between them.

**Start and update.** One thing this package does not have and three it does.
It does not sign its own release assets with ML-DSA-65 against a committed
public key; that is the primitives package, and the distinction is worth
keeping because it is the strongest of the four.

What every release here carries:

- A **SLSA provenance attestation**, tying the published tarball to the commit
  and workflow that built it. `npm audit signatures` checks it, and it can be
  read straight from the registry without asking us for anything.
- A **CycloneDX SBOM** as a GitHub Release asset, at a permanent unauthenticated
  URL rather than an expiring build artifact.
- **Exact pins** on `@noble/ciphers`, `@noble/curves` and `@noble/hashes`, so
  the code performing the symmetric and classical work cannot change without a
  release of this package.

That is a checkable release, not a bare one.

**Protect records, enforce policy, retain history.** None apply. This is a
transport with no persistence: no logs, no stored state, no records to retain.
Session keys live for the session. There is no long-term verification question
here because nothing signed here is kept.

**What this is not for.** Public HTTPS endpoints. This is a protocol between
systems you control on both ends. A public server terminates TLS 1.3 with the
standardised `X25519MLKEM768` group at the edge, and `TLS.md` covers that.
Assessing this package tells a buyer nothing about the edge.

## Agility

**Inherited.** The primitives, their two interchangeable backends and the
parameter-set surface belong to `kxco-post-quantum`. See that package's
`AGILITY.md`.

**The addition: the wire has a version byte.** Both `ClientHello` and
`ServerHello` begin with `version = 0x01`, and the HKDF info string is
`kxco-pq-tls-v1`. A v2 handshake can therefore be introduced and distinguished
on the wire rather than guessed at, and the key schedule of one version cannot
collide with another. That is the mechanism a protocol migration needs, and it
is present.

**The limit: there is no negotiation.** The version byte identifies; it does
not negotiate. Algorithms are fixed in the frame layout, and the frame sizes
say so: 1184 bytes of ML-KEM-768 encapsulation key and 32 of X25519 in the
ClientHello, 1088 and 32 in the ServerHello. Changing parameter set changes
those sizes, so it is a new protocol version and a release of this package, not
a configuration.

Practically, a migration is the add-then-remove staging the primitives package
documents in `MIGRATION.md`, run at the protocol level: deploy responders that
accept v1 and v2, then move initiators, then retire v1. Nothing here does that
for you, and nothing here prevents it.

## Lifecycle

**Supported versions.** One line moving forward, matching the rest of the
family. Fixes land in the next release rather than being backported.

**An inconsistency in this package's own pins.** `@noble/ciphers`,
`@noble/curves` and `@noble/hashes` are all declared at exactly `2.4.0`, no
range. `kxco-post-quantum` is declared `^1.3.0`. So the three dependencies that
do not perform the post-quantum key exchange are pinned, and the one that does
is not.

That is measurable rather than theoretical: the tree this package's evidence
bundle was last built from resolved `^1.3.0` to **1.4.0**, while the current
primitives release is 1.7.2. `02-primitives.json` in the bundle records the
resolved version, and it is the version any claim about that bundle applies to.

Changing it is a policy decision with a maintenance cost, since an exact pin
means every primitives release needs a release of this package. It has not been
made.

**Ceiling.** No hardware ceiling. The cost that scales is the handshake: an
ML-KEM-768 encapsulation and an X25519 exchange per connection, plus two
ML-DSA-65 operations per side when mutual authentication is on. Record
throughput afterwards is AES-256-GCM and is not the constraint. A design that
opens many short connections pays the handshake repeatedly, and connection
reuse is the answer rather than a faster parameter set.

The frame sizes are also a real constraint on constrained links: a ClientHello
is 1218 bytes and a ServerHello 1122, both well past a single small MTU.

**Roadmap.** No external audit of this protocol, no bug bounty, no formal
analysis. The handshake is this package's own design, and it has not had the
independent review the primitives beneath it have had. That is the most
significant open item on this package and it is stated here rather than left to
be noticed.

## Correcting this document

Every claim here is checkable against `src/`. If one does not match, that is a
defect worth reporting through the repository's issues.
