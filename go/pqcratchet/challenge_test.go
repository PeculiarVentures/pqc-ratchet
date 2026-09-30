package pqcratchet_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"testing"

	pqc "github.com/PeculiarVentures/pqc-ratchet/go/pqcratchet"
)

func TestComputeChallengeVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/challenge_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var f struct {
		Vectors []struct {
			ServerSigningPub string `json:"serverSigningPub"`
			ClientSigningPub string `json:"clientSigningPub"`
			Pin              string `json:"pin"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(f.Vectors) < 6 {
		t.Fatalf("expected at least 6 vectors, got %d", len(f.Vectors))
	}
	for i, v := range f.Vectors {
		server, err := hex.DecodeString(v.ServerSigningPub)
		if err != nil {
			t.Fatalf("vector %d: server key: %v", i, err)
		}
		client, err := hex.DecodeString(v.ClientSigningPub)
		if err != nil {
			t.Fatalf("vector %d: client key: %v", i, err)
		}
		if got := pqc.ComputeChallenge(server, client); got != v.Pin {
			t.Errorf("vector %d: got %s, want %s", i, got, v.Pin)
		}
	}
}

func TestComputeChallengeAlwaysSixDigits(t *testing.T) {
	sixDigits := regexp.MustCompile(`^[0-9]{6}$`)
	for i := 0; i < 2000; i++ {
		server := []byte{byte(i), byte(i >> 8)}
		client := []byte{byte(i >> 8), byte(i), 0xff}
		if pin := pqc.ComputeChallenge(server, client); !sixDigits.MatchString(pin) {
			t.Fatalf("input %d: PIN %q is not 6 digits", i, pin)
		}
	}
	if pin := pqc.ComputeChallenge(nil, nil); !sixDigits.MatchString(pin) {
		t.Fatalf("empty keys: PIN %q is not 6 digits", pin)
	}
}

type challengeV2Vector struct {
	Note             string `json:"note"`
	ServerSigningPub string `json:"serverSigningPub"`
	ClientSigningPub string `json:"clientSigningPub"`
	ClientNonce      string `json:"clientNonce"`
	ServerNonce      string `json:"serverNonce"`
	Commit           string `json:"commit"`
	Pin              string `json:"pin"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func TestChallengeV2Vectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/challenge_v2_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var f struct {
		Vectors []challengeV2Vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(f.Vectors) < 6 {
		t.Fatalf("expected at least 6 vectors, got %d", len(f.Vectors))
	}
	for i, v := range f.Vectors {
		server, client := mustHex(t, v.ServerSigningPub), mustHex(t, v.ClientSigningPub)
		cn, sn, commit := mustHex(t, v.ClientNonce), mustHex(t, v.ServerNonce), mustHex(t, v.Commit)

		gotCommit, err := pqc.CommitChallengeNonce(client, cn)
		if err != nil {
			t.Fatalf("vector %d (%s): commit: %v", i, v.Note, err)
		}
		if !bytes.Equal(gotCommit, commit) {
			t.Errorf("vector %d (%s): commit %x, want %x", i, v.Note, gotCommit, commit)
		}
		if !pqc.VerifyChallengeCommit(client, cn, commit) {
			t.Errorf("vector %d (%s): commit does not verify", i, v.Note)
		}
		pin, err := pqc.ComputeChallengeV2(server, client, cn, sn)
		if err != nil {
			t.Fatalf("vector %d (%s): pin: %v", i, v.Note, err)
		}
		if pin != v.Pin {
			t.Errorf("vector %d (%s): pin %s, want %s", i, v.Note, pin, v.Pin)
		}
	}
}

func TestChallengeV2NonceSizes(t *testing.T) {
	key := []byte("client key")
	good := make([]byte, pqc.ChallengeNonceSize)
	for _, n := range [][]byte{nil, make([]byte, pqc.ChallengeNonceSize-1), make([]byte, pqc.ChallengeNonceSize+1)} {
		if _, err := pqc.CommitChallengeNonce(key, n); err == nil {
			t.Errorf("CommitChallengeNonce accepted %d-byte nonce", len(n))
		}
		if _, err := pqc.ComputeChallengeV2(key, key, n, good); err == nil {
			t.Errorf("ComputeChallengeV2 accepted %d-byte client nonce", len(n))
		}
		if _, err := pqc.ComputeChallengeV2(key, key, good, n); err == nil {
			t.Errorf("ComputeChallengeV2 accepted %d-byte server nonce", len(n))
		}
		if pqc.VerifyChallengeCommit(key, n, make([]byte, 32)) {
			t.Errorf("VerifyChallengeCommit accepted %d-byte nonce", len(n))
		}
	}
	commit, err := pqc.CommitChallengeNonce(key, good)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range [][]byte{nil, commit[:31], append(append([]byte{}, commit...), 0)} {
		if pqc.VerifyChallengeCommit(key, good, c) {
			t.Errorf("VerifyChallengeCommit accepted %d-byte commit", len(c))
		}
	}
}

func TestVerifyChallengeCommitRejectsBitFlips(t *testing.T) {
	key := []byte("client signing key")
	nonce, err := pqc.NewChallengeNonce()
	if err != nil {
		t.Fatal(err)
	}
	commit, err := pqc.CommitChallengeNonce(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !pqc.VerifyChallengeCommit(key, nonce, commit) {
		t.Fatal("valid commit rejected")
	}
	flip := func(b []byte, i int) []byte {
		c := append([]byte{}, b...)
		c[i/8] ^= 1 << (i % 8)
		return c
	}
	for _, bit := range []int{0, 7, 100, 255} {
		if pqc.VerifyChallengeCommit(key, flip(nonce, bit), commit) {
			t.Errorf("accepted nonce with bit %d flipped", bit)
		}
		if pqc.VerifyChallengeCommit(key, nonce, flip(commit, bit)) {
			t.Errorf("accepted commit with bit %d flipped", bit)
		}
	}
	for _, bit := range []int{0, 9, 8*len(key) - 1} {
		if pqc.VerifyChallengeCommit(flip(key, bit), nonce, commit) {
			t.Errorf("accepted client key with bit %d flipped", bit)
		}
	}
}

func TestNewChallengeNonce(t *testing.T) {
	a, err := pqc.NewChallengeNonce()
	if err != nil {
		t.Fatal(err)
	}
	b, err := pqc.NewChallengeNonce()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != pqc.ChallengeNonceSize || len(b) != pqc.ChallengeNonceSize {
		t.Fatalf("nonce lengths %d, %d; want %d", len(a), len(b), pqc.ChallengeNonceSize)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two nonces are equal")
	}
}
