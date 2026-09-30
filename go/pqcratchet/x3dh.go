package pqcratchet

// x3dh.go implements the KEM-based X3DH key agreement.
//
// The original X3DH protocol uses DH computations to establish a shared secret.
// Since ML-KEM is a KEM (encapsulate/decapsulate), not a DH primitive, we
// restructure the computation while preserving the forward secrecy and
// authentication properties.
//
// Alice (initiator) side — AuthenticateA:
//
//	(ct1, ss1) = KEM.Encap(rnd, SPK_B)          // signed pre-key: mutual auth + FS
//	(ct2, ss2) = KEM.Encap(rnd, IK_B.ex)        // identity key: mutual auth
//	EK_A       = KEM.GenerateKeyPair(rnd)        // ephemeral keypair: becomes initial ratchet key
//	[(ct4, ss3) = KEM.Encap(rnd, OPK_B)]       // forward secrecy against SPK compromise
//	T  = transcript (see buildInitiatorTranscript)
//	th = SHA-256(T)
//	RK || XS = HKDF(IKM=0xFF×32 || ss1 || ss2 [|| ss3], salt=th, info="pqcratchet/v2/KEMInit", L=64)
//
//	Sent to Bob: { ctx, IK_A.ex, EK_A.pub, ct1, ct2, [ct4], Sig(IK_A.sig, T) }
//
// T covers Bob's identity keys, signed pre-key and one-time pre-key, so Bob
// can check the signature before he reserves or decapsulates with any key.
//
// Bob (responder) side — AuthenticateB:
//
//	rebuild T from ctx and Bob's own keys; verify Sig(IK_A.sig, T) before decapsulating
//	ss1 = KEM.Decap(SPK_B.sk, ct1)
//	ss2 = KEM.Decap(IK_B.ex.sk, ct2)
//	[ss3 = KEM.Decap(OPK_B.sk, ct4)]
//	RK || XS = HKDF(IKM=0xFF×32 || ss1 || ss2 [|| ss3], salt=th, info="pqcratchet/v2/KEMInit", L=64)
//
// RK is the initial root key. XS is the exporter secret behind
// Session.ExportKeyingMaterial. th is the transcript hash, which also becomes
// part of the session AD, so every message is bound to this handshake.
//
// # Session context
//
// ctx is an opaque, application-defined byte string (at most
// MaxSessionContextSize bytes). The library carries it in the PreKeyMessage,
// signs it, and mixes it into every key. It does not interpret it. A
// rendezvous deployment would put the session id, origin, requested actions,
// protocol negotiation outcome and expiry in it, in a canonical encoding.
// The responder MUST check the context against what it expects before acting
// on the session, because a valid signature proves only that the initiator
// asserted it.
//
// The ephemeral keypair EK_A is sent to Bob as BaseKey and becomes Alice's
// initial ratchet encapsulation key for the Double Ratchet.
//
// # Deniability tradeoff
//
// The original X3DH provides cryptographic deniability because DH is symmetric:
// anyone with the public keys can compute the same SK, so a transcript doesn't
// prove which party sent it (X3DH spec §4.4).
//
// This KEM-based variant loses deniability. Because KEMs don't provide implicit
// authentication (anyone can encapsulate against Bob's public keys), Alice must
// explicitly sign the transcript with ML-DSA-65 to authenticate herself. This
// signature is non-repudiable — Alice cannot plausibly deny sending the initial
// message. The X3DH spec §4.5 warns explicitly against replacing DH-based
// mutual authentication with signatures for exactly this reason. This is a
// necessary tradeoff in the PQC setting, not a flaw, but applications with
// strong deniability requirements should note it.
//
// # State of the art for PQ X3DH
//
// Several approaches to this tradeoff exist in the literature:
//
// Signal's PQXDH (Kret, Schmidt 2023) — the deployed production protocol —
// takes a hybrid approach: it keeps the full classical X3DH intact and injects
// a KEM shared secret alongside the DH outputs. This preserves classical
// deniability and backward compatibility but authentication still relies on
// classical hardness (discrete log), not PQ hardness. See:
// https://signal.org/docs/specifications/pqxdh/
//
// Hashimoto et al. (PKC 2022, ePrint 2021/616) — the approach this package
// follows — replaces DH entirely with KEM + signature and proves security
// under PQ assumptions. It shows how to progressively restore deniability
// using ring signatures or NIZKs at the cost of additional complexity.
//
// Brendel et al. SPQR (PKC 2022, ePrint 2021/769) achieves deniability using
// designated-verifier signatures. K-Waay (Collins et al., ASIACCS 2025,
// ePrint 2024/120) achieves deniability using a split-KEM without ring
// signatures and is currently the most efficient deniable construction.
//
// This package implements the Hashimoto et al. direct-signature variant
// (weakly deniable per their terminology) because it maps cleanly to NIST
// standard primitives (ML-KEM-768, ML-DSA-65) without requiring ring
// signatures or NIZKs. Applications requiring deniability should use PQXDH
// or evaluate K-Waay.

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KEMInitiatorResult is returned by AuthenticateA.
// The ciphertexts and InitiatorSig must be sent to the responder inside the PreKeyMessage.
type KEMInitiatorResult struct {
	// RootKey is the derived 32-byte session root key.
	RootKey []byte

	// TranscriptHash is SHA-256 of the signed X3DH transcript. It is not secret.
	// Both sides compute the same value; it is part of the session AD.
	TranscriptHash []byte

	// SessionContext is the application context bound into the transcript.
	SessionContext []byte

	// EphemeralKP is Alice's ephemeral KEM keypair.
	// EphemeralKP.Public is sent in the PreKeyMessage as the BaseKey.
	// EphemeralKP.Private becomes Alice's initial ratchet key.
	EphemeralKP *HybridKEMKeyPair

	// CT1: encap against Bob's signed pre-key (for ss1).
	CT1 *HybridKEMCiphertext
	// CT2: encap against Bob's identity exchange key (for ss2).
	CT2 *HybridKEMCiphertext
	// CT4: encap against Bob's one-time pre-key (for ss3), nil if no OPK.
	CT4 *HybridKEMCiphertext

	// InitiatorSig is Alice's ML-DSA-65 signature over the X3DH transcript
	// built by buildInitiatorTranscript. It proves Alice holds the private key
	// for her signing public key, and binds the session context, protocol
	// version and Bob's keys into her statement.
	InitiatorSig []byte

	// exporterSecret backs Session.ExportKeyingMaterial. It is unexported so
	// that logging or serialising the result cannot leak it, and it is
	// zeroed once the session has taken a copy.
	exporterSecret []byte
}

// ResponderKeys are the responder's public keys as the initiator saw them in
// the bundle. They are bound into the signed transcript, so a PreKeyMessage
// addressed to one responder, or to one of its pre-keys, is rejected by any
// other.
type ResponderKeys struct {
	SigningPubBytes  []byte              // IK_B.sig public key bytes (DSAPublicKeySize)
	ExchangePub      *HybridKEMPublicKey // IK_B.ex
	SignedPreKeyPub  *HybridKEMPublicKey // SPK_B
	OneTimePreKeyPub *HybridKEMPublicKey // OPK_B, or nil when no one-time pre-key is used
}

// AuthenticateA performs the X3DH key agreement from the initiator's side.
//
// This implements the KEM-based X3DH initiator protocol, following the structure
// of the X3DH specification [1] §3.3 adapted for KEMs as in Hashimoto et al. [2].
//
// Mutual authentication: Alice signs the X3DH transcript with her ML-DSA-65
// signing key. Bob verifies this signature before accepting the session.
// Without it, any party holding Bob's public bundle could produce valid
// CT1/CT2 and impersonate Alice.
//
// Note: this construction provides authentication but NOT deniability.
// The ML-DSA-65 signature over the transcript is Alice-specific and cannot
// be produced by any other party, creating a non-repudiable record.
// See X3DH spec §4.4–4.5 for the original deniability discussion.
//
//	[1] https://signal.org/docs/specifications/x3dh/
//	[2] Hashimoto et al. PKC 2022. https://eprint.iacr.org/2021/616
//
// Parameters:
//   - initiatorSigningKey:  Alice's ML-DSA-65 signing private key (IK_A.sig)
//   - initiatorExchangePub: Alice's KEM exchange public key (IK_A.ex)
//   - responder:            Bob's identity key, signed pre-key and optional
//     one-time pre-key from the bundle
//   - sessionContext:       application context to bind (may be empty)
func AuthenticateA(
	initiatorSigningKey *DSAPrivateKey,
	initiatorExchangePub *HybridKEMPublicKey,
	responder *ResponderKeys,
	sessionContext []byte,
) (*KEMInitiatorResult, error) {
	return authenticateA(rand.Reader, initiatorSigningKey, initiatorExchangePub, responder, sessionContext)
}

func authenticateA(
	r io.Reader,
	initiatorSigningKey *DSAPrivateKey,
	initiatorExchangePub *HybridKEMPublicKey,
	responder *ResponderKeys,
	sessionContext []byte,
) (*KEMInitiatorResult, error) {
	if len(sessionContext) > MaxSessionContextSize {
		return nil, ErrSessionContextTooLarge
	}
	if err := responder.validate(); err != nil {
		return nil, err
	}

	// KEM1 = Encap(SPK_B) → ss1
	ct1, ss1, err := Encapsulate(r, responder.SignedPreKeyPub)
	if err != nil {
		return nil, fmt.Errorf("x3dh KEM1 (SPK): %w", err)
	}

	// KEM2 = Encap(IK_B.ex) → ss2
	ct2, ss2, err := Encapsulate(r, responder.ExchangePub)
	if err != nil {
		return nil, fmt.Errorf("x3dh KEM2 (IK): %w", err)
	}

	// Generate ephemeral KEM keypair EK_A.
	// EK_A.pub is sent as BaseKey and becomes the initial ratchet key.
	// EK_A contributes to forward secrecy: compromise of long-term keys after
	// session establishment cannot recover the session key because EK_A.priv
	// is discarded immediately after use.
	ephemeralKP, err := GenerateKEMKeyPair(r)
	if err != nil {
		return nil, fmt.Errorf("x3dh ephemeral keygen: %w", err)
	}

	// Optional KEM3 = Encap(OPK_B) → ss3 (one-time pre-key, if available)
	var ct4 *HybridKEMCiphertext
	var ss3 []byte
	if responder.OneTimePreKeyPub != nil {
		ct4, ss3, err = Encapsulate(r, responder.OneTimePreKeyPub)
		if err != nil {
			return nil, fmt.Errorf("x3dh KEM3 (OPK): %w", err)
		}
	}

	ctx := cloneBytes(sessionContext)
	transcript := buildInitiatorTranscript(ctx, responder, initiatorExchangePub, ct1, ct2, &ephemeralKP.Public, ct4)
	th := sha256.Sum256(transcript)

	rootKey, exporterSecret, err := deriveKEMRootKey(ss1, ss2, ss3, th[:])
	if err != nil {
		return nil, err
	}

	sig, err := Sign(initiatorSigningKey, transcript)
	if err != nil {
		return nil, fmt.Errorf("x3dh sign transcript: %w", err)
	}

	return &KEMInitiatorResult{
		RootKey:        rootKey,
		TranscriptHash: th[:],
		SessionContext: ctx,
		EphemeralKP:    ephemeralKP,
		CT1:            ct1,
		CT2:            ct2,
		CT4:            ct4,
		InitiatorSig:   sig,
		exporterSecret: exporterSecret,
	}, nil
}

// KEMResponderResult is returned by AuthenticateB.
type KEMResponderResult struct {
	RootKey        []byte
	TranscriptHash []byte
	exporterSecret []byte // see KEMInitiatorResult.exporterSecret
}

// AuthenticateB performs X3DH from the responder's side.
//
// Rebuilds the transcript from the received values and Bob's own public keys,
// and verifies Alice's ML-DSA-65 signature over it before decapsulating.
// Returns ErrInvalidSignature if verification fails; the caller must not
// proceed to create a session in that case. A PreKeyMessage that was built
// for a different responder, pre-key, protocol version or session context
// fails here.
//
// responder must describe Bob's own keys. Set responder.OneTimePreKeyPub
// exactly when oneTimePreKeyPriv is non-nil.
//
//   - identityExchangePriv:  Bob's identity exchange private key (IK_B.ex)
//   - signedPreKeyPriv:      Bob's signed pre-key private key (SPK_B)
//   - oneTimePreKeyPriv:     Bob's one-time pre-key private key (OPK_B), or nil
//   - responder:             Bob's own public keys (IK_B.sig, IK_B.ex, SPK_B, OPK_B)
//   - initiatorSigningPub:   Alice's ML-DSA-65 signing public key
//   - initiatorExchangePub:  Alice's KEM exchange public key (IK_A.ex)
//   - baseKey:               Alice's ephemeral KEM public key (EK_A.pub)
//   - ct1, ct2:              ciphertexts from Alice's X3DH computation
//   - ct4:                   one-time pre-key ciphertext, or nil
//   - sessionContext:        the context carried in the PreKeyMessage
//   - initiatorSig:          Alice's signature over the transcript
func AuthenticateB(
	identityExchangePriv *HybridKEMPrivateKey,
	signedPreKeyPriv *HybridKEMPrivateKey,
	oneTimePreKeyPriv *HybridKEMPrivateKey,
	responder *ResponderKeys,
	initiatorSigningPub *DSAPublicKey,
	initiatorExchangePub *HybridKEMPublicKey,
	baseKey *HybridKEMPublicKey,
	ct1, ct2 *HybridKEMCiphertext,
	ct4 *HybridKEMCiphertext,
	sessionContext []byte,
	initiatorSig []byte,
) (*KEMResponderResult, error) {
	if (oneTimePreKeyPriv == nil) != (responder == nil || responder.OneTimePreKeyPub == nil) {
		return nil, fmt.Errorf("pqcratchet: responder one-time pre-key public and private keys must be supplied together")
	}
	th, err := verifyInitiatorTranscript(responder, initiatorSigningPub, initiatorExchangePub, baseKey, ct1, ct2, ct4, sessionContext, initiatorSig)
	if err != nil {
		return nil, err
	}
	return deriveResponderKeys(th, identityExchangePriv, signedPreKeyPriv, oneTimePreKeyPriv, ct1, ct2, ct4)
}

// verifyInitiatorTranscript rebuilds the transcript from the received values
// and the responder's own keys and verifies InitiatorSig. It touches no
// private key material, so a caller can run it before reserving a one-time
// pre-key. Returns the transcript hash.
func verifyInitiatorTranscript(
	responder *ResponderKeys,
	initiatorSigningPub *DSAPublicKey,
	initiatorExchangePub *HybridKEMPublicKey,
	baseKey *HybridKEMPublicKey,
	ct1, ct2, ct4 *HybridKEMCiphertext,
	sessionContext []byte,
	initiatorSig []byte,
) ([]byte, error) {
	if len(sessionContext) > MaxSessionContextSize {
		return nil, ErrSessionContextTooLarge
	}
	if err := responder.validate(); err != nil {
		return nil, err
	}
	// Guard both directions of OPK mismatch explicitly. The transcript would
	// fail to verify anyway, but a named error says what went wrong.
	switch {
	case responder.OneTimePreKeyPub != nil && ct4 == nil:
		return nil, fmt.Errorf("x3dh: have OPK private key but initiator sent no CT4")
	case responder.OneTimePreKeyPub == nil && ct4 != nil:
		return nil, fmt.Errorf("x3dh: initiator sent CT4 but no OPK private key available")
	}
	// Verify BEFORE any decapsulation, so Bob's decapsulation cannot be used
	// as an oracle against arbitrary ciphertexts.
	transcript := buildInitiatorTranscript(sessionContext, responder, initiatorExchangePub, ct1, ct2, baseKey, ct4)
	if !Verify(initiatorSigningPub, transcript, initiatorSig) {
		return nil, ErrInvalidSignature
	}
	th := sha256.Sum256(transcript)
	return th[:], nil
}

// deriveResponderKeys decapsulates and derives the root key and exporter
// secret. Call it only after verifyInitiatorTranscript has succeeded.
func deriveResponderKeys(
	th []byte,
	identityExchangePriv, signedPreKeyPriv, oneTimePreKeyPriv *HybridKEMPrivateKey,
	ct1, ct2, ct4 *HybridKEMCiphertext,
) (*KEMResponderResult, error) {
	// ss1 = Decap(SPK_B.sk, ct1)
	ss1, err := Decapsulate(signedPreKeyPriv, ct1)
	if err != nil {
		return nil, fmt.Errorf("x3dh decap KEM1 (SPK): %w", err)
	}

	// ss2 = Decap(IK_B.ex, ct2)
	ss2, err := Decapsulate(identityExchangePriv, ct2)
	if err != nil {
		return nil, fmt.Errorf("x3dh decap KEM2 (IK): %w", err)
	}

	// Optional ss3 = Decap(OPK_B.sk, ct4)
	var ss3 []byte
	switch {
	case oneTimePreKeyPriv != nil && ct4 != nil:
		ss3, err = Decapsulate(oneTimePreKeyPriv, ct4)
		if err != nil {
			return nil, fmt.Errorf("x3dh decap KEM3 (OPK): %w", err)
		}
	case oneTimePreKeyPriv != nil && ct4 == nil:
		return nil, fmt.Errorf("x3dh: have OPK private key but initiator sent no CT4")
	case oneTimePreKeyPriv == nil && ct4 != nil:
		return nil, fmt.Errorf("x3dh: initiator sent CT4 but no OPK private key available")
	}

	rootKey, exporterSecret, err := deriveKEMRootKey(ss1, ss2, ss3, th)
	if err != nil {
		return nil, err
	}
	return &KEMResponderResult{RootKey: rootKey, TranscriptHash: th, exporterSecret: exporterSecret}, nil
}

func (k *ResponderKeys) validate() error {
	if k == nil || k.ExchangePub == nil || k.SignedPreKeyPub == nil {
		return fmt.Errorf("pqcratchet: responder keys incomplete")
	}
	if len(k.SigningPubBytes) != DSAPublicKeySize {
		return fmt.Errorf("pqcratchet: responder signing key must be %d bytes, got %d", DSAPublicKeySize, len(k.SigningPubBytes))
	}
	return nil
}

// buildInitiatorTranscript constructs the byte string that Alice signs and Bob verifies.
//
// Layout (all integers big-endian):
//
//	"pqcratchet/v2/X3DH"
//	u8   WireVersion
//	u32  len(ProtocolID) || ProtocolID
//	u32  len(ctx)        || ctx
//	[32] SHA-256(IK_B.sig)
//	IK_B.ex || SPK_B
//	IK_A.ex || CT1 || CT2 || EK_A.pub
//	u8   hasOPK [|| OPK_B || CT4]
//
// The label, version and protocol id stop a signature made for one protocol
// or version from verifying under another. The context binds the application
// session (for example rendezvous session id and origin). Bob's keys, one-time
// pre-key included, stop a PreKeyMessage addressed to one responder or one
// pre-key from being accepted for any other. IK_A.ex binds Alice's exchange
// key directly into her signed statement. Variable-length fields are
// length-prefixed and everything else is fixed size, so the encoding is
// unambiguous.
//
// The caller guarantees that responder.OneTimePreKeyPub and ct4 are either
// both set or both nil.
func buildInitiatorTranscript(
	sessionContext []byte,
	responder *ResponderKeys,
	initiatorExchangePub *HybridKEMPublicKey,
	ct1, ct2 *HybridKEMCiphertext,
	baseKey *HybridKEMPublicKey,
	ct4 *HybridKEMCiphertext,
) []byte {
	respSigHash := sha256.Sum256(responder.SigningPubBytes)
	size := len(transcriptLabel) + 1 + 4 + len(ProtocolID) + 4 + len(sessionContext) + 32 +
		HybridPublicKeySize*4 + HybridCiphertextSize*2 + 1
	if ct4 != nil {
		size += HybridPublicKeySize + HybridCiphertextSize
	}
	t := make([]byte, 0, size)
	t = append(t, transcriptLabel...)
	t = append(t, WireVersion)
	t = appendUint32(t, uint32(len(ProtocolID)))
	t = append(t, ProtocolID...)
	t = appendUint32(t, uint32(len(sessionContext)))
	t = append(t, sessionContext...)
	t = append(t, respSigHash[:]...)
	t = append(t, responder.ExchangePub[:]...)
	t = append(t, responder.SignedPreKeyPub[:]...)
	t = append(t, initiatorExchangePub[:]...)
	t = append(t, ct1[:]...)
	t = append(t, ct2[:]...)
	t = append(t, baseKey[:]...)
	if ct4 != nil {
		t = append(t, 0x01)
		t = append(t, responder.OneTimePreKeyPub[:]...)
		t = append(t, ct4[:]...)
	} else {
		t = append(t, 0x00)
	}
	return t
}

// deriveKEMRootKey builds the key material and runs HKDF to produce the
// 32-byte root key and the 32-byte exporter secret.
//
//	KM = 0xFF×32 || ss1 || ss2 [|| ss3]
//	RK || XS = HKDF-SHA256(KM, salt=th, info="pqcratchet/v2/KEMInit", length=64)
//
// The 0xFF prefix ensures KM is never all-zero and provides domain separation.
// The salt is the transcript hash, so the keys depend on everything the
// initiator signed (context, protocol version, both identities, every
// ciphertext) and not only on the KEM outputs. Both sides compute th before
// deriving, so no extra agreement is needed.
func deriveKEMRootKey(ss1, ss2, ss3, transcriptHash []byte) (rootKey, exporterSecret []byte, err error) {
	// Each shared secret must be exactly 32 bytes (the hybrid KEM combined output).
	// These assertions guard against a future refactor where Decapsulate might return
	// a wrong-length slice, which would silently weaken the IKM without error.
	if len(ss1) != 32 {
		return nil, nil, fmt.Errorf("pqcratchet: x3dh ss1 must be 32 bytes, got %d", len(ss1))
	}
	if len(ss2) != 32 {
		return nil, nil, fmt.Errorf("pqcratchet: x3dh ss2 must be 32 bytes, got %d", len(ss2))
	}
	if ss3 != nil && len(ss3) != 32 {
		return nil, nil, fmt.Errorf("pqcratchet: x3dh ss3 (OPK) must be 32 bytes, got %d", len(ss3))
	}
	if len(transcriptHash) != 32 {
		return nil, nil, fmt.Errorf("pqcratchet: x3dh transcript hash must be 32 bytes, got %d", len(transcriptHash))
	}
	domainSep := make([]byte, 32)
	for i := range domainSep {
		domainSep[i] = 0xFF
	}

	keyMaterial := make([]byte, 0, 32+len(ss1)+len(ss2)+len(ss3))
	keyMaterial = append(keyMaterial, domainSep...)
	keyMaterial = append(keyMaterial, ss1...)
	keyMaterial = append(keyMaterial, ss2...)
	keyMaterial = append(keyMaterial, ss3...)

	hkdfReader := hkdf.New(sha256.New, keyMaterial, transcriptHash, infoKEMInit)

	out := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, out); err != nil {
		return nil, nil, fmt.Errorf("x3dh HKDF: %w", err)
	}
	rootKey = append([]byte(nil), out[:32]...)
	exporterSecret = append([]byte(nil), out[32:]...)
	for i := range out {
		out[i] = 0
	}
	return rootKey, exporterSecret, nil
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
