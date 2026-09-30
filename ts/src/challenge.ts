import { concat, constantTimeEqual, randomBytes, sha256 } from "./crypto.js";

/** Byte length of the commit-then-reveal nonces. */
export const CHALLENGE_NONCE_SIZE = 32;

/** Byte length of a commit (a SHA-256 digest). */
const CHALLENGE_COMMIT_SIZE = 32;

const enc = new TextEncoder();
const CHALLENGE_LABEL = enc.encode("pqcratchet/v1/Challenge");
const COMMIT_LABEL = enc.encode("pqcratchet/v1/Commit");
const CHALLENGE2_LABEL = enc.encode("pqcratchet/v1/Challenge2");

function pinFromDigest(digest: Uint8Array): string {
  const n = new DataView(digest.buffer, digest.byteOffset, 8).getBigUint64(0, false);
  return (n % 1_000_000n).toString().padStart(6, "0");
}

function checkNonce(name: string, nonce: Uint8Array): void {
  if (nonce.length !== CHALLENGE_NONCE_SIZE) {
    throw new Error(`pqcratchet: ${name} must be ${CHALLENGE_NONCE_SIZE} bytes, got ${nonce.length}`);
  }
}

/**
 * computeChallenge returns the 6-digit pairing PIN:
 * BE-uint64(SHA-256("pqcratchet/v1/Challenge" || SHA-256(serverSigningPub) || SHA-256(clientSigningPub))[0:8]) mod 10^6.
 * Matches Go's ComputeChallenge byte for byte.
 * @deprecated A man-in-the-middle can grind keys offline to match this PIN; use computeChallengeV2.
 */
export async function computeChallenge(
  serverSigningPub: Uint8Array,
  clientSigningPub: Uint8Array,
): Promise<string> {
  return pinFromDigest(
    await sha256(concat(CHALLENGE_LABEL, await sha256(serverSigningPub), await sha256(clientSigningPub))),
  );
}

/** newChallengeNonce returns CHALLENGE_NONCE_SIZE bytes from crypto.getRandomValues. */
export function newChallengeNonce(): Uint8Array {
  return randomBytes(CHALLENGE_NONCE_SIZE);
}

/**
 * commitChallengeNonce returns SHA-256("pqcratchet/v1/Commit" || SHA-256(clientSigningPub) || clientNonce),
 * which the client sends before seeing the server's nonce. Throws on a wrong nonce size.
 */
export async function commitChallengeNonce(
  clientSigningPub: Uint8Array,
  clientNonce: Uint8Array,
): Promise<Uint8Array> {
  checkNonce("client nonce", clientNonce);
  return sha256(concat(COMMIT_LABEL, await sha256(clientSigningPub), clientNonce));
}

/** verifyChallengeCommit reports in constant time whether commit opens to clientNonce for clientSigningPub. */
export async function verifyChallengeCommit(
  clientSigningPub: Uint8Array,
  clientNonce: Uint8Array,
  commit: Uint8Array,
): Promise<boolean> {
  if (clientNonce.length !== CHALLENGE_NONCE_SIZE || commit.length !== CHALLENGE_COMMIT_SIZE) return false;
  return constantTimeEqual(await commitChallengeNonce(clientSigningPub, clientNonce), commit);
}

/**
 * computeChallengeV2 returns the 6-digit pairing PIN:
 * BE-uint64(SHA-256("pqcratchet/v1/Challenge2" || SHA-256(serverSigningPub) || SHA-256(clientSigningPub) || clientNonce || serverNonce)[0:8]) mod 10^6.
 * Matches Go's ComputeChallengeV2 byte for byte. Throws on wrong nonce sizes.
 */
export async function computeChallengeV2(
  serverSigningPub: Uint8Array,
  clientSigningPub: Uint8Array,
  clientNonce: Uint8Array,
  serverNonce: Uint8Array,
): Promise<string> {
  checkNonce("client nonce", clientNonce);
  checkNonce("server nonce", serverNonce);
  return pinFromDigest(
    await sha256(
      concat(CHALLENGE2_LABEL, await sha256(serverSigningPub), await sha256(clientSigningPub), clientNonce, serverNonce),
    ),
  );
}
