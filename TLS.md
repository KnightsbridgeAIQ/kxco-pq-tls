# Post-quantum TLS on the KXCO endpoints

How to get `X25519MLKEM768` on the wire for `relay.kxco.ai` and `chain.kxco.ai`, and — more importantly — how to **prove** you got it.

Everything below was measured on OpenSSL 3.5.6 with Node 26.1.0, not read off a specification. Where the measured behaviour differs from what you would expect, it says so.

---

## The short version

Production TLS to the KXCO endpoints uses the hybrid key exchange `X25519MLKEM768`, standardised in [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024) (August 2026; it was draft-ietf-tls-ecdhe-mlkem). It combines X25519 with ML-KEM-768, so an attacker must break **both** to recover the session key.

You need **OpenSSL 3.5 or later**. That means Node 24.7+ or 22.20+, or a build linked against your own OpenSSL 3.5.

```bash
node -p "process.versions.openssl"    # must be 3.5.x or later
```

This is transport confidentiality only. It says nothing about who is at the other end: that is what the ML-DSA-87 or ML-DSA-65 identity layer is for.

---

## Client: Node

```js
import { request } from 'node:https'

const req = request('https://relay.kxco.ai/intents', {
  method: 'POST',
  minVersion: 'TLSv1.3',
  groups: 'X25519MLKEM768:X25519',   // PQ first, classical as fallback
  headers: { 'content-type': 'application/json' },
})
```

For `fetch`, set it on a dispatcher:

```js
import { Agent, setGlobalDispatcher } from 'undici'

setGlobalDispatcher(new Agent({
  connect: { minVersion: 'TLSv1.3', groups: 'X25519MLKEM768:X25519' },
}))
```

`kxco-pq-chain` and `kxco-pq-network` both use the platform `fetch`, so a global dispatcher covers them without either package needing a TLS option of its own.

### Drop the fallback only if you mean it

`'X25519MLKEM768'` on its own, with no `:X25519`, means a peer that cannot do the hybrid group gets no connection. That is the right setting for a service that talks only to KXCO endpoints. It is the wrong setting for a general-purpose HTTP client, which will start failing against unrelated hosts.

---

## Server: Node

```js
import { createServer } from 'node:https'

createServer({
  key, cert,
  minVersion: 'TLSv1.3',
  groups: 'X25519MLKEM768:X25519',
}, app)
```

### Measured caveat: on the server, `groups` is a preference, not a restriction

This surprised us, so it is worth stating precisely.

With a Node server configured `groups: 'X25519MLKEM768'` — the PQ group **only**, no fallback listed:

| Client offers | Result |
|---|---|
| default group list | connects, negotiates `X25519MLKEM768` |
| `X25519` only | **connects anyway**, on a classical group |

The same test against `openssl s_server -groups X25519MLKEM768` behaves differently:

| Client offers | Result |
|---|---|
| `X25519MLKEM768` | connects, negotiates `X25519MLKEM768` |
| `X25519` only | **handshake failure, alert 40** |

So configuring the group on a Node server puts the hybrid first and gets it used by any client that supports it, but it does **not** refuse a client that does not. If you need refusal, terminate TLS in front of Node — nginx, HAProxy or a load balancer linked against OpenSSL 3.5 — and set the group there.

Do not assume the setting enforced something because the connection succeeded. Measure it.

---

## Proving it

`getEphemeralKeyInfo()` in Node returns `{}` for this group, so it cannot tell you what was negotiated. The one command that answers the question:

```bash
echo | openssl s_client -connect relay.kxco.ai:443 -tls1_3 2>/dev/null \
  | grep -i "Negotiated TLS1.3 group"
```

```
Negotiated TLS1.3 group: X25519MLKEM768
```

**No output means no hybrid group.** A silent success is a classical handshake.

Run it as a control too, so you know the command itself works:

```bash
echo | openssl s_client -connect relay.kxco.ai:443 -tls1_3 -groups X25519 2>/dev/null \
  | grep -i "Negotiated TLS1.3 group"
```

That should print `X25519`, or nothing. If both invocations print the same thing, your `-groups` flag is not doing what you think.

Your `openssl` binary must itself be 3.5+ — check with `openssl version`. An older client cannot offer the group, so it will report a classical result no matter what the server supports, and you will conclude the server is misconfigured when it is not.

### Measured, 3 September 2026

OpenSSL 3.5.6, against the live endpoints:

| endpoint | negotiated group |
|---|---|
| `relay.kxco.ai:443` | `X25519MLKEM768` |
| `chain.kxco.ai:443` | `X25519MLKEM768` |
| `cloudflare.com:443` (control) | `X25519MLKEM768` |

The control matters in the other direction from the one you might expect. A
host that also negotiates the hybrid group proves the local client can offer
it, so a KXCO endpoint reporting classical would be the endpoint's doing and
not the test's. Re-measure after any change to the edge; this is a property of
the deployed configuration, not of the repository, and nothing in CI holds it
in place.

---

## nginx

```nginx
ssl_protocols          TLSv1.3;
ssl_ecdh_curve         X25519MLKEM768:X25519;
ssl_prefer_server_ciphers off;
```

Requires nginx built against OpenSSL 3.5+. `nginx -V 2>&1 | grep -o 'OpenSSL [0-9.]*'` tells you what it was built with, which is not necessarily what `openssl version` reports on the same box.

---

## Where this fits

TLS protects the channel. It says nothing about who is at the other end, and it leaves nothing behind afterwards.

- **Channel** — `X25519MLKEM768`, this document.
- **Who signed it**: ML-DSA-87 or ML-DSA-65 on the intent or the envelope. Survives the connection closing, and can be checked years later by someone who was never on it.
- **Whether that signer is still trusted** — a live registry lookup, `anchored+live` in `kxco-pq-network`.

A record-now-decrypt-later adversary is defeated by the first. An adversary who obtained a signing key is not, and no amount of transport security helps: that is what revocation is for.

---

## Server configuration is out of band

This file documents what to set. Applying it to `relay.kxco.ai` and `chain.kxco.ai` is an operations change made outside this repository, and this document does not assert it has been made. Run the `openssl s_client` check above against the live endpoint and read the answer.
