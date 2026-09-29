package pqcratchet

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// ComputeChallenge returns the 6-digit pairing PIN: BE-uint64(SHA-256("pqcratchet/v1/Challenge" || SHA-256(serverSigningPub) || SHA-256(clientSigningPub))[0:8]) mod 10^6.
func ComputeChallenge(serverSigningPub, clientSigningPub []byte) string {
	st := sha256.Sum256(serverSigningPub)
	ct := sha256.Sum256(clientSigningPub)
	h := sha256.New()
	h.Write([]byte("pqcratchet/v1/Challenge"))
	h.Write(st[:])
	h.Write(ct[:])
	digest := h.Sum(nil)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint64(digest[:8])%1_000_000)
}
