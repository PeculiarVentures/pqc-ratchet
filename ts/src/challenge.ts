import { concat, sha256 } from "./crypto.js";

const CHALLENGE_LABEL = new TextEncoder().encode("pqcratchet/v1/Challenge");

/**
 * computeChallenge returns the 6-digit pairing PIN:
 * BE-uint64(SHA-256("pqcratchet/v1/Challenge" || SHA-256(serverSigningPub) || SHA-256(clientSigningPub))[0:8]) mod 10^6.
 * Matches Go's ComputeChallenge byte for byte.
 */
export async function computeChallenge(
  serverSigningPub: Uint8Array,
  clientSigningPub: Uint8Array,
): Promise<string> {
  const digest = await sha256(
    concat(CHALLENGE_LABEL, await sha256(serverSigningPub), await sha256(clientSigningPub)),
  );
  const n = new DataView(digest.buffer, digest.byteOffset, 8).getBigUint64(0, false);
  return (n % 1_000_000n).toString().padStart(6, "0");
}
