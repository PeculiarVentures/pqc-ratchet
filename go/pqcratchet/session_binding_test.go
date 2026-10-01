package pqcratchet_test

import (
	"bytes"
	"errors"
	"testing"

	pqc "github.com/PeculiarVentures/pqc-ratchet/go/pqcratchet"
)

// establishWithContext runs a full handshake through the wire format with the
// given session context and returns both sessions and the marshalled PKM.
func establishWithContext(t *testing.T, ctx []byte) (alice, bob *pqc.Session, pkmBytes []byte, bobID *pqc.Identity) {
	t.Helper()
	aliceID, bobIdentity := mustIdentities(t)
	bundleWire, err := pqc.MakeBundleWire(bobIdentity, 0, 0)
	must(t, err, "MakeBundleWire")
	bundle, err := pqc.ParseBundleWire(bundleWire)
	must(t, err, "ParseBundleWire")

	aliceSess, result, err := pqc.CreateSessionInitiatorWithContext(aliceID, bundle, ctx)
	must(t, err, "CreateSessionInitiatorWithContext")
	pkmBytes = pqc.MarshalPreKeyMessageWire(result.ToPreKeyMessageWire(aliceID, bundle))

	bobSess, err := responderFromBytes(bobIdentity, pkmBytes)
	must(t, err, "CreateSessionResponder")
	return aliceSess, bobSess, pkmBytes, bobIdentity
}

func responderFromBytes(id *pqc.Identity, pkmBytes []byte) (*pqc.Session, error) {
	raw, err := pqc.UnmarshalPreKeyMessageWire(bytes.NewReader(pkmBytes))
	if err != nil {
		return nil, err
	}
	pkm, err := pqc.ParsePreKeyMessageWire(raw)
	if err != nil {
		return nil, err
	}
	return pqc.CreateSessionResponder(id, pkm)
}

// ctxOffset is where the session context starts in a marshalled PKM:
// version(1) + registrationID(4) + signedPreKeyIndex(4) + oneTimePreKeyIndex(4) + ctxLen(4).
const ctxOffset = 1 + 4 + 4 + 4 + 4

func TestSessionContextBoundAndDelivered(t *testing.T) {
	ctx := []byte(`{"sid":"s_123","origin":"https://payroll.example","ops":["x509/sign"]}`)
	alice, bob, _, _ := establishWithContext(t, ctx)

	if !bytes.Equal(alice.SessionContext, ctx) || !bytes.Equal(bob.SessionContext, ctx) {
		t.Fatalf("session context not delivered: alice=%q bob=%q", alice.SessionContext, bob.SessionContext)
	}
	if len(alice.TranscriptHash) != 32 || !bytes.Equal(alice.TranscriptHash, bob.TranscriptHash) {
		t.Fatal("transcript hashes differ between peers")
	}
	sendRecv(t, alice, bob, "hello")
	sendRecv(t, bob, alice, "reply")
}

func TestSessionContextTamperRejected(t *testing.T) {
	ctx := []byte("sid=s_123;origin=https://a.example")
	aliceID, bobID := mustIdentities(t)
	bundle := mustBundle(t, bobID)
	_, result, err := pqc.CreateSessionInitiatorWithContext(aliceID, bundle, ctx)
	must(t, err, "CreateSessionInitiatorWithContext")
	pkmBytes := pqc.MarshalPreKeyMessageWire(result.ToPreKeyMessageWire(aliceID, bundle))

	// A relay rewrites one byte of the origin. The length is unchanged, so the
	// frame still parses; only the signature can catch it.
	tampered := append([]byte(nil), pkmBytes...)
	tampered[ctxOffset+len(ctx)-1] ^= 0x01
	if _, err := responderFromBytes(bobID, tampered); !errors.Is(err, pqc.ErrInvalidSignature) {
		t.Fatalf("tampered context: got %v, want ErrInvalidSignature", err)
	}
	if bobID.PreKeys[0] == nil {
		t.Fatal("rejected PreKeyMessage consumed the OPK")
	}
	// The untampered frame is still accepted afterwards.
	if _, err := responderFromBytes(bobID, pkmBytes); err != nil {
		t.Fatalf("honest PreKeyMessage rejected after a tampered one: %v", err)
	}
}

func TestSessionContextReplacedRejected(t *testing.T) {
	aliceID, bobID := mustIdentities(t)
	bundle := mustBundle(t, bobID)
	_, result, err := pqc.CreateSessionInitiatorWithContext(aliceID, bundle, []byte("origin=https://a.example"))
	must(t, err, "CreateSessionInitiatorWithContext")

	w := result.ToPreKeyMessageWire(aliceID, bundle)
	w.SessionContext = []byte("origin=https://evil.example")
	if _, err := responderFromBytes(bobID, pqc.MarshalPreKeyMessageWire(w)); !errors.Is(err, pqc.ErrInvalidSignature) {
		t.Fatalf("replaced context: got %v, want ErrInvalidSignature", err)
	}

	w.SessionContext = nil
	if _, err := responderFromBytes(bobID, pqc.MarshalPreKeyMessageWire(w)); !errors.Is(err, pqc.ErrInvalidSignature) {
		t.Fatalf("stripped context: got %v, want ErrInvalidSignature", err)
	}
}

func TestPreKeyMessageBoundToResponder(t *testing.T) {
	// Bob and Carol share a signed pre-key index and OPK index layout, so the
	// only thing distinguishing them is their keys. A PKM for Bob must not be
	// accepted by Carol.
	aliceID, bobID := mustIdentities(t)
	carolID, err := pqc.GenerateIdentity(3, 1, 1)
	must(t, err, "GenerateIdentity carol")

	bundle := mustBundle(t, bobID)
	_, result, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "CreateSessionInitiator")
	pkmBytes := pqc.MarshalPreKeyMessageWire(result.ToPreKeyMessageWire(aliceID, bundle))

	if _, err := responderFromBytes(carolID, pkmBytes); !errors.Is(err, pqc.ErrInvalidSignature) {
		t.Fatalf("PKM for Bob presented to Carol: got %v, want ErrInvalidSignature", err)
	}
	if carolID.PreKeys[0] == nil {
		t.Fatal("Carol's OPK was consumed by a rejected PKM")
	}
}

func TestSessionContextTooLarge(t *testing.T) {
	aliceID, bobID := mustIdentities(t)
	bundle := mustBundle(t, bobID)
	big := make([]byte, pqc.MaxSessionContextSize+1)
	if _, _, err := pqc.CreateSessionInitiatorWithContext(aliceID, bundle, big); !errors.Is(err, pqc.ErrSessionContextTooLarge) {
		t.Fatalf("oversized context on create: got %v", err)
	}

	// A frame that claims an oversized context is rejected before allocation.
	_, result, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "CreateSessionInitiator")
	b := pqc.MarshalPreKeyMessageWire(result.ToPreKeyMessageWire(aliceID, bundle))
	b[ctxOffset-4], b[ctxOffset-3], b[ctxOffset-2], b[ctxOffset-1] = 0x7F, 0xFF, 0xFF, 0xFF
	if _, err := pqc.UnmarshalPreKeyMessageWire(bytes.NewReader(b)); !errors.Is(err, pqc.ErrSessionContextTooLarge) {
		t.Fatalf("oversized context length on parse: got %v", err)
	}

	max := make([]byte, pqc.MaxSessionContextSize)
	if _, _, err := pqc.CreateSessionInitiatorWithContext(aliceID, bundle, max); err != nil {
		t.Fatalf("context at the limit should be accepted: %v", err)
	}
}

func TestVersion1FramesRejected(t *testing.T) {
	if pqc.WireVersion != 0x02 {
		t.Fatalf("WireVersion = 0x%02x, want 0x02", pqc.WireVersion)
	}
	aliceID, bobID := mustIdentities(t)
	bundle := mustBundle(t, bobID)
	aliceSess, result, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "CreateSessionInitiator")

	pkm := pqc.MarshalPreKeyMessageWire(result.ToPreKeyMessageWire(aliceID, bundle))
	pkm[0] = 0x01
	if _, err := pqc.UnmarshalPreKeyMessageWire(bytes.NewReader(pkm)); err == nil {
		t.Fatal("v1 PreKeyMessage accepted")
	}
	wire, err := aliceSess.Seal([]byte("x"))
	must(t, err, "Seal")
	wire[0] = 0x01
	if _, err := pqc.UnmarshalSignedMessage(wire); err == nil {
		t.Fatal("v1 signed message accepted")
	}
}

func TestADContainsTranscriptHash(t *testing.T) {
	alice, bob, _, _ := establishWithContext(t, []byte("ctx"))
	want := 2*pqc.HybridPublicKeySize + 32
	if len(alice.AD) != want || len(bob.AD) != want {
		t.Fatalf("AD length: alice=%d bob=%d want=%d", len(alice.AD), len(bob.AD), want)
	}
	if !bytes.Equal(alice.AD, bob.AD) {
		t.Fatal("AD differs between peers")
	}
	if !bytes.Equal(alice.AD[2*pqc.HybridPublicKeySize:], alice.TranscriptHash) {
		t.Fatal("AD does not end with the transcript hash")
	}
}

func TestExportKeyingMaterial(t *testing.T) {
	alice, bob, _, _ := establishWithContext(t, []byte("sid=s_1"))

	a, err := alice.ExportKeyingMaterial("goodkey approval", []byte("op=x509/sign"), 32)
	must(t, err, "alice export")
	b, err := bob.ExportKeyingMaterial("goodkey approval", []byte("op=x509/sign"), 32)
	must(t, err, "bob export")
	if !bytes.Equal(a, b) {
		t.Fatal("exporter output differs between peers")
	}

	otherLabel, _ := alice.ExportKeyingMaterial("other", []byte("op=x509/sign"), 32)
	otherCtx, _ := alice.ExportKeyingMaterial("goodkey approval", []byte("op=unwrap"), 32)
	if bytes.Equal(a, otherLabel) || bytes.Equal(a, otherCtx) {
		t.Fatal("exporter output does not depend on label and context")
	}

	// Label/context boundary is length-prefixed, so shifting bytes across it changes the output.
	x, _ := alice.ExportKeyingMaterial("ab", []byte("c"), 32)
	y, _ := alice.ExportKeyingMaterial("a", []byte("bc"), 32)
	if bytes.Equal(x, y) {
		t.Fatal("exporter label/context encoding is ambiguous")
	}

	// Stable across ratchet steps.
	sendRecv(t, alice, bob, "one")
	sendRecv(t, bob, alice, "two")
	sendRecv(t, alice, bob, "three")
	after, _ := bob.ExportKeyingMaterial("goodkey approval", []byte("op=x509/sign"), 32)
	if !bytes.Equal(a, after) {
		t.Fatal("exporter output changed after ratchet steps")
	}

	// Distinct sessions give distinct outputs.
	alice2, _, _, _ := establishWithContext(t, []byte("sid=s_1"))
	c, _ := alice2.ExportKeyingMaterial("goodkey approval", []byte("op=x509/sign"), 32)
	if bytes.Equal(a, c) {
		t.Fatal("two sessions produced the same exporter output")
	}

	// A shorter request is a prefix of a longer one (HKDF-Expand property).
	long, _ := alice.ExportKeyingMaterial("goodkey approval", []byte("op=x509/sign"), 64)
	if !bytes.Equal(long[:32], a) {
		t.Fatal("exporter output is not HKDF-Expand prefix-consistent")
	}

	for _, n := range []int{0, -1, 255*32 + 1} {
		if _, err := alice.ExportKeyingMaterial("x", nil, n); !errors.Is(err, pqc.ErrExporterLength) {
			t.Fatalf("length %d: got %v, want ErrExporterLength", n, err)
		}
	}
	if _, err := alice.ExportKeyingMaterial("x", nil, 255*32); err != nil {
		t.Fatalf("max length rejected: %v", err)
	}
}

func TestEmptyContextSessionsDiffer(t *testing.T) {
	// Two handshakes between the same identities with the same (empty)
	// context must still produce different ADs, because the transcript hash
	// covers the fresh ciphertexts.
	aliceID, bobID := mustIdentities(t)
	bw, err := pqc.MakeBundleWire(bobID, 0, -1)
	must(t, err, "MakeBundleWire")
	bundle, err := pqc.ParseBundleWire(bw)
	must(t, err, "ParseBundleWire")
	s1, _, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "session 1")
	s2, _, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "session 2")
	if bytes.Equal(s1.AD, s2.AD) {
		t.Fatal("two sessions between the same identities share an AD")
	}
}

func TestOneTimePreKeyIndexRewriteRejected(t *testing.T) {
	// A relay rewrites the OPK index in a valid PreKeyMessage. Bob must reject
	// it at the signature check and leave every OPK slot untouched, so the
	// relay cannot drain his one-time pre-keys by replaying one message with
	// each index.
	aliceID, err := pqc.GenerateIdentity(1, 1, 0)
	must(t, err, "GenerateIdentity alice")
	bobID, err := pqc.GenerateIdentity(2, 1, 3)
	must(t, err, "GenerateIdentity bob")

	bundle := mustBundle(t, bobID) // uses OPK 0
	_, result, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "CreateSessionInitiator")
	w := result.ToPreKeyMessageWire(aliceID, bundle)

	for _, idx := range []uint32{1, 2} {
		w.OneTimePreKeyIndex = idx
		_, err := responderFromBytes(bobID, pqc.MarshalPreKeyMessageWire(w))
		if !errors.Is(err, pqc.ErrInvalidSignature) {
			t.Fatalf("OPK index rewritten to %d: got %v, want ErrInvalidSignature", idx, err)
		}
	}
	for i, kp := range bobID.PreKeys {
		if kp == nil {
			t.Fatalf("OPK %d was consumed by a rejected PreKeyMessage", i)
		}
	}

	// The unmodified message still works and consumes exactly OPK 0.
	w.OneTimePreKeyIndex = 0
	if _, err := responderFromBytes(bobID, pqc.MarshalPreKeyMessageWire(w)); err != nil {
		t.Fatalf("honest PreKeyMessage rejected: %v", err)
	}
	if bobID.PreKeys[0] != nil || bobID.PreKeys[1] == nil || bobID.PreKeys[2] == nil {
		t.Fatal("honest PreKeyMessage consumed the wrong OPK")
	}
}

func TestOPKSlotStateNotRevealed(t *testing.T) {
	// A PreKeyMessage naming a consumed OPK must fail the same way as one with
	// a bad signature, so error text does not reveal which slots are live.
	aliceID, bobID := mustIdentities(t)
	bundle := mustBundle(t, bobID)
	_, result, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "CreateSessionInitiator")
	pkm := pqc.MarshalPreKeyMessageWire(result.ToPreKeyMessageWire(aliceID, bundle))
	if _, err := responderFromBytes(bobID, pkm); err != nil {
		t.Fatalf("honest PreKeyMessage rejected: %v", err)
	}
	if _, err := responderFromBytes(bobID, pkm); !errors.Is(err, pqc.ErrInvalidSignature) {
		t.Fatalf("replay against consumed OPK: got %v, want ErrInvalidSignature", err)
	}
}

func TestSignedPreKeyIndexRewriteRejected(t *testing.T) {
	aliceID, err := pqc.GenerateIdentity(1, 1, 0)
	must(t, err, "GenerateIdentity alice")
	bobID, err := pqc.GenerateIdentity(2, 2, 0)
	must(t, err, "GenerateIdentity bob")
	bw, err := pqc.MakeBundleWire(bobID, 0, -1)
	must(t, err, "MakeBundleWire")
	bundle, err := pqc.ParseBundleWire(bw)
	must(t, err, "ParseBundleWire")
	_, result, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "CreateSessionInitiator")
	w := result.ToPreKeyMessageWire(aliceID, bundle)
	w.SignedPreKeyIndex = 1
	if _, err := responderFromBytes(bobID, pqc.MarshalPreKeyMessageWire(w)); !errors.Is(err, pqc.ErrInvalidSignature) {
		t.Fatalf("SPK index rewritten: got %v, want ErrInvalidSignature", err)
	}
}

func TestNonCanonicalFlagsRejected(t *testing.T) {
	aliceID, bobID := mustIdentities(t)
	bundle := mustBundle(t, bobID)
	aliceSess, result, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "CreateSessionInitiator")

	// hasCT4 sits right after the fixed-size fields that follow the context.
	pkm := pqc.MarshalPreKeyMessageWire(result.ToPreKeyMessageWire(aliceID, bundle))
	hasCT4 := ctxOffset + len(result.SessionContext) + pqc.DSAPublicKeySize + pqc.DSASignatureSize +
		2*pqc.HybridPublicKeySize + 2*pqc.HybridCiphertextSize
	if pkm[hasCT4] != 0x01 {
		t.Fatalf("test offset wrong: hasCT4 byte is 0x%02x", pkm[hasCT4])
	}
	pkm[hasCT4] = 0x02
	if _, err := pqc.UnmarshalPreKeyMessageWire(bytes.NewReader(pkm)); err == nil {
		t.Fatal("hasCT4 = 0x02 accepted")
	}

	bw, err := pqc.MakeBundleWire(bobID, 0, -1)
	must(t, err, "MakeBundleWire")
	bb := pqc.MarshalBundleWire(bw)
	bb[len(bb)-1] = 0x02 // hasOneTimePreKey is the last byte when there is no OPK
	if _, err := pqc.UnmarshalBundleWire(bytes.NewReader(bb)); err == nil {
		t.Fatal("hasOneTimePreKey = 0x02 accepted")
	}

	enc, err := aliceSess.EncryptMessage([]byte("x"))
	must(t, err, "EncryptMessage")
	inner := pqc.MarshalMessageProtocol(&pqc.ParsedMessageProtocol{
		Counter: uint32(enc.Counter), SenderRatchetPub: enc.NewRatchetPub,
		RatchetCT: enc.RatchetCT, CipherText: enc.Ciphertext,
	})
	inner[4+pqc.HybridPublicKeySize] = 0x02
	if _, err := pqc.UnmarshalMessageProtocol(inner); err == nil {
		t.Fatal("hasRatchetCT = 0x02 accepted")
	}
}

func mustBundle(t *testing.T, id *pqc.Identity) *pqc.PreKeyBundle {
	t.Helper()
	bw, err := pqc.MakeBundleWire(id, 0, 0)
	must(t, err, "MakeBundleWire")
	b, err := pqc.ParseBundleWire(bw)
	must(t, err, "ParseBundleWire")
	return b
}
