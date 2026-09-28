package pqcratchet_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"testing"

	pqc "github.com/PeculiarVentures/pqc-ratchet/go/pqcratchet"
)

func TestComputeChallengeVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/challenge_vectors.json")
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
