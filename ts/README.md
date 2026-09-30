# @peculiarventures/pqc-ratchet

> **v0 — no API or wire stability guarantees.**

Post-quantum Double Ratchet + X3DH in TypeScript.  
Wire-compatible with [github.com/PeculiarVentures/pqc-ratchet](https://github.com/PeculiarVentures/pqc-ratchet) (Go).

Works in **browsers, Node ≥ 18, Deno, and Bun** — uses only WebCrypto and `@noble/post-quantum`.

## Algorithms

| Role | Algorithm | Standard |
|------|-----------|----------|
| Signing | ML-DSA-65 | FIPS 204 |
| Key exchange | ML-KEM-768 + X25519 (hybrid) | FIPS 203 + RFC 7748 |
| Message encryption | AES-256-GCM | FIPS 197 |
| Message authentication | HMAC-SHA-256 | FIPS 198 |
| KDF | HKDF-SHA-256 | SP 800-56C |

`@noble/post-quantum` is not FIPS-validated (no CMVP certificate), but is independently audited by Trail of Bits and implements FIPS 203/204 correctly. For environments requiring CMVP validation, use the Go implementation with a FIPS-validated Go crypto module.

## NIST position on hybrid key establishment

NIST SP 800-227 ipd (2024) explicitly permits hybrid key establishment constructions that
combine a FIPS-approved algorithm with a non-FIPS algorithm, provided the FIPS-approved
component alone meets the required security strength:

> A hybrid key-establishment scheme combining an approved scheme with a non-approved scheme
> is permitted when the approved scheme independently provides the required security strength.

**ML-KEM-768 alone satisfies FIPS 203.** X25519 is defense-in-depth — present for
cryptographic agility, not for FIPS compliance. Its inclusion does not invalidate the
FIPS 203 contribution. For strict FIPS-only deployments the X25519 leg can be removed
without changing the rest of the protocol.

Note: `@noble/post-quantum` is not FIPS-validated (no CMVP certificate) but implements
FIPS 203/204 correctly and is independently audited by Trail of Bits. For CMVP-validated
deployments, use the Go implementation with a FIPS-validated Go crypto module.

## Install

```bash
npm install @peculiarventures/pqc-ratchet
```

## Quick start

```typescript
import {
  generateIdentity,
  createSessionInitiator,
  createSessionResponder,
} from "@peculiarventures/pqc-ratchet";

// Generate identities
const alice = await generateIdentity(1, 1, 10);
const bob   = await generateIdentity(2, 1, 10);

// Bob publishes a prekey bundle
const bundle = {
  registrationId:      bob.id,
  identitySigningPub:  bob.signingKey.publicKey,
  identityExchangePub: bob.exchangeKey.publicKey,
  signedPreKeyPub:     bob.signedPreKeys[0].publicKey,
  signedPreKeyIndex:   0,
  signedPreKeySig:     bob.signedPreKeySigs[0],
  oneTimePreKeyPub:    bob.preKeys[0]!.publicKey,
  oneTimePreKeyIndex:  0,
};

// Alice initiates a session
const { session: aliceSess, preKeyMessage } = await createSessionInitiator(alice, bundle);

// Bob receives and creates his session
const bobSess = await createSessionResponder(bob, preKeyMessage);

// Alice encrypts and gets a wire-ready frame
const wire = await aliceSess.seal(new TextEncoder().encode("hello"));

// Bob verifies and decrypts
const plaintext = await bobSess.open(wire);
console.log(new TextDecoder().decode(plaintext)); // "hello"
```

The `seal()` and `open()` methods handle wire marshalling, HMAC construction, and
signing internally. For advanced use (custom transports, batching, audit tooling)
the lower-level `encryptMessage()` / `decryptMessage()` + `marshal*` functions are
also exported.

### Binding a session to its context

When a relay or other intermediary carries the handshake, pass a session context. It is
signed by the initiator, delivered in the PreKeyMessage, and mixed into every key. The
responder must check it before acting.

```typescript
const ctx = new TextEncoder().encode(JSON.stringify({ sid: "s_123", origin: location.origin }));
const { session: aliceSess, preKeyMessage } = await createSessionInitiator(alice, bundle, ctx);
const bobSess = await createSessionResponder(bob, preKeyMessage);
// bobSess.sessionContext must equal what Bob expects before he acts on the session.

// Keying material both peers share, e.g. a channel binding value for approvals.
const cb = await bobSess.exportKeyingMaterial("goodkey approval", opDigest, 32);
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `@noble/post-quantum` | ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204) |
| `@noble/curves` | X25519 |
| `@noble/hashes` | SHA-256 (via noble transitive dep) |

WebCrypto (built-in) handles AES-256-GCM, HMAC-SHA-256, HKDF-SHA-256.

## Tests

```bash
npm test
```

Tests cover KEM round-trip, DSA sign/verify, the symmetric chain, X3DH on both sides, full sessions, multi-turn messaging, OPK restoration on auth failure, the seal/open API, session context and responder binding, the exporter, and wire version rejection.

## Go interop

The wire format (public key and ciphertext layouts, HKDF info strings, transcript structure, wire version 0x02) is identical to the Go implementation. The interop test also checks that both sides agree on the session context, the transcript hash and exporter output. A Go server and TypeScript client can exchange messages directly.

Private key storage differs: Go stores the 64-byte ML-KEM seed; TypeScript stores the 2400-byte expanded secret key. Both produce identical public keys and ciphertexts.
