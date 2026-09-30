package pqcratchet

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// ChallengeNonceSize is the byte length of the commit-then-reveal nonces.
const ChallengeNonceSize = 32

const (
	commitLabel     = "pqcratchet/v1/Commit"
	challenge2Label = "pqcratchet/v1/Challenge2"
)

// ComputeChallenge returns the 6-digit pairing PIN: BE-uint64(SHA-256("pqcratchet/v1/Challenge" || SHA-256(serverSigningPub) || SHA-256(clientSigningPub))[0:8]) mod 10^6.
//
// Deprecated: a man-in-the-middle can grind keys offline to match this PIN; use ComputeChallengeV2.
func ComputeChallenge(serverSigningPub, clientSigningPub []byte) string {
	st := sha256.Sum256(serverSigningPub)
	ct := sha256.Sum256(clientSigningPub)
	h := sha256.New()
	h.Write([]byte("pqcratchet/v1/Challenge"))
	h.Write(st[:])
	h.Write(ct[:])
	return pinFromDigest(h.Sum(nil))
}

func pinFromDigest(digest []byte) string {
	return fmt.Sprintf("%06d", binary.BigEndian.Uint64(digest[:8])%1_000_000)
}

func checkNonce(name string, nonce []byte) error {
	if len(nonce) != ChallengeNonceSize {
		return fmt.Errorf("pqcratchet: %s must be %d bytes, got %d", name, ChallengeNonceSize, len(nonce))
	}
	return nil
}

// NewChallengeNonce returns ChallengeNonceSize bytes from crypto/rand.
func NewChallengeNonce() ([]byte, error) {
	n := make([]byte, ChallengeNonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}

// CommitChallengeNonce returns SHA-256("pqcratchet/v1/Commit" || SHA-256(clientSigningPub) || clientNonce), which the client sends before seeing the server's nonce.
func CommitChallengeNonce(clientSigningPub, clientNonce []byte) ([]byte, error) {
	if err := checkNonce("client nonce", clientNonce); err != nil {
		return nil, err
	}
	ct := sha256.Sum256(clientSigningPub)
	h := sha256.New()
	h.Write([]byte(commitLabel))
	h.Write(ct[:])
	h.Write(clientNonce)
	return h.Sum(nil), nil
}

// VerifyChallengeCommit reports in constant time whether commit opens to clientNonce for clientSigningPub.
func VerifyChallengeCommit(clientSigningPub, clientNonce, commit []byte) bool {
	if len(commit) != sha256.Size {
		return false
	}
	want, err := CommitChallengeNonce(clientSigningPub, clientNonce)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(want, commit) == 1
}

// ComputeChallengeV2 returns the 6-digit pairing PIN: BE-uint64(SHA-256("pqcratchet/v1/Challenge2" || SHA-256(serverSigningPub) || SHA-256(clientSigningPub) || clientNonce || serverNonce)[0:8]) mod 10^6.
func ComputeChallengeV2(serverSigningPub, clientSigningPub, clientNonce, serverNonce []byte) (string, error) {
	if err := checkNonce("client nonce", clientNonce); err != nil {
		return "", err
	}
	if err := checkNonce("server nonce", serverNonce); err != nil {
		return "", err
	}
	st := sha256.Sum256(serverSigningPub)
	ct := sha256.Sum256(clientSigningPub)
	h := sha256.New()
	h.Write([]byte(challenge2Label))
	h.Write(st[:])
	h.Write(ct[:])
	h.Write(clientNonce)
	h.Write(serverNonce)
	return pinFromDigest(h.Sum(nil)), nil
}
