# pqc-ratchet

Post-quantum Double Ratchet + X3DH in Go and TypeScript.

```
go/   — Go implementation (FIPS 203/204, circl, standard library)
ts/   — TypeScript implementation (WebCrypto, @noble/post-quantum)
```

Both implementations share the same binary wire format and are verified by a
cross-language interop test (`go/pqcratchet/interop_test.go`).

## Algorithms

| Role | Algorithm | Standard |
|------|-----------|----------|
| Signing | ML-DSA-65 | FIPS 204 |
| Key exchange | ML-KEM-768 + X25519 (hybrid) | FIPS 203 + RFC 7748 |
| Message encryption | AES-256-GCM | FIPS 197 |
| Message authentication | HMAC-SHA-256 | FIPS 198 |
| KDF | HKDF-SHA-256 | SP 800-56C |

## Quick start

```bash
# Go
cd go && go test ./pqcratchet/...

# TypeScript
cd ts && npm install && npm test

# Cross-language interop test (Go ↔ TypeScript on the same wire format)
cd ts && npx tsc && cd ..
cd go && go test ./pqcratchet/... -run TestInteropGoTS -v
```

### Sending a message (TypeScript)

```typescript
import { generateIdentity, createSessionInitiator, createSessionResponder }
  from "@peculiarventures/pqc-ratchet";

const alice = await generateIdentity(1, 2, 10);
const bob   = await generateIdentity(2, 2, 10);

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

const { session: aliceSess, preKeyMessage } = await createSessionInitiator(alice, bundle);
const bobSess = await createSessionResponder(bob, preKeyMessage);

// seal() and open() handle marshalling, HMAC, and signing internally
const wire = await aliceSess.seal(new TextEncoder().encode("hello"));
const pt   = await bobSess.open(wire);
console.log(new TextDecoder().decode(pt)); // "hello"
```

### Sending a message (Go)

Install: `go get github.com/PeculiarVentures/pqc-ratchet/go`

```go
import pqc "github.com/PeculiarVentures/pqc-ratchet/go/pqcratchet"

aliceID, _ := pqc.GenerateIdentity(1, 2, 10)
bobID, _   := pqc.GenerateIdentity(2, 2, 10)

bundleWire, _ := pqc.MakeBundleWire(bobID, 0, 0)
bundle, _      := pqc.ParseBundleWire(bundleWire)
aliceSess, result, _ := pqc.CreateSessionInitiator(aliceID, bundle)
pkmBytes  := pqc.MarshalPreKeyMessageWire(result.ToPreKeyMessageWire(aliceID, bundle))
raw, _    := pqc.UnmarshalPreKeyMessageWire(bytes.NewReader(pkmBytes))
pkm, _    := pqc.ParsePreKeyMessageWire(raw)
bobSess, _ := pqc.CreateSessionResponder(bobID, pkm)

wire, _      := aliceSess.Seal([]byte("hello"))
plaintext, _ := bobSess.Open(wire)
fmt.Println(string(plaintext)) // "hello"
```

### Pairing code

Both peers display a 6-digit PIN to confirm they hold each other's identity keys. In the formulas and API names below, "server" means the responder (the party that published the prekey bundle) and "client" means the initiator. These are protocol roles, not network roles. A phone that joins a relay session by outbound connection is still the server here if it published the bundle. The PIN binds both keys and two nonces fixed by commit-then-reveal:

```
thumb(k) = SHA-256(k)                                       (raw 32 bytes)
nonce    = 32 random bytes                                   (crypto/rand; WebCrypto getRandomValues)
commit   = SHA-256("pqcratchet/v1/Commit" || thumb(clientSigningPub) || clientNonce)
digest   = SHA-256("pqcratchet/v1/Challenge2" || thumb(serverSigningPub) || thumb(clientSigningPub) || clientNonce || serverNonce)
PIN      = big-endian uint64(digest[0:8]) mod 1_000_000, zero-padded to 6 digits
```

Flow (implemented by the application):

1. Client picks `clientNonce` and sends `commit`.
2. Server replies with a fresh `serverNonce`, only after it has received the commit.
3. Client reveals `clientNonce`.
4. Server checks it against the commit (`VerifyChallengeCommit`), then both sides show the PIN.

Each side fixes its nonce before learning the other's, so a man-in-the-middle cannot grind keys offline and matches with probability 10^-6 per attempt.

**Application requirements.** The 10^-6 bound holds only if the application enforces the flow:

- Server (responder): at most one pending commit at a time, across all sessions, not just per session. A commit is pending from receipt until it is revealed and resolved, or expires; a new commit while one is pending is rejected. With k concurrent commits an attacker learns the client's PIN and reveals only on the matching server session, succeeding with probability k·10^-6.
- This rule is enforced by the responder itself, per identity, and never delegated to an intermediary. When sessions reach the responder through a relay, the relay can open any number of sessions to it, so the count of pending commits must be kept on the responder device across every session it has joined. A relay-side limit does not satisfy the requirement, because a compromised relay would simply not apply it.
- Server: a fresh random `serverNonce` per commit, sent only after the commit is received and never reused; one commit per session; verify the commit before showing any PIN; a mismatch or timeout aborts the pairing (no retry on the same session).
- Client: obtain and verify the server bundle before committing; a fresh `clientNonce` per pairing attempt; reveal only after receiving `serverNonce`; never reveal for a commit it did not send.

| | Go | TypeScript |
|---|---|---|
| Nonce | `NewChallengeNonce` | `newChallengeNonce` |
| Commit | `CommitChallengeNonce` | `commitChallengeNonce` |
| Verify (constant time) | `VerifyChallengeCommit` | `verifyChallengeCommit` |
| PIN | `ComputeChallengeV2` | `computeChallengeV2` |

The earlier `ComputeChallenge` / `computeChallenge` (label `"pqcratchet/v1/Challenge"`, keys only) is deprecated: without nonces, a man-in-the-middle who can generate ~10^6 key pairs can make both sides show the same PIN.

Shared vectors live in `go/pqcratchet/testdata/challenge_v2_vectors.json` (and `challenge_vectors.json` for the deprecated PIN). Regenerate both with `go run ./cmd/challenge_vectors_gen pqcratchet/testdata` from `go/`.

## Repository layout

```
go/
  pqcratchet/        core library
  cmd/interop_gen/   standalone fixture generator
  DESIGN.md          full design rationale and security analysis
  README.md

ts/
  src/               TypeScript source
  scripts/           interop_verify.mjs
  SECURITY_REVIEW.md TS-specific security review
  README.md
```

## v0 stability

No API or wire format stability guarantees. Not production-ready.
