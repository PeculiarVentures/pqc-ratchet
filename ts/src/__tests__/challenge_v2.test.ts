/**
 * challenge_v2.test.ts — checks the commit-then-reveal pairing code against go/pqcratchet/testdata/challenge_v2_vectors.json.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  CHALLENGE_NONCE_SIZE,
  commitChallengeNonce,
  computeChallengeV2,
  newChallengeNonce,
  verifyChallengeCommit,
} from "../index.js";

interface Vector {
  note: string;
  serverSigningPub: string;
  clientSigningPub: string;
  clientNonce: string;
  serverNonce: string;
  commit: string;
  pin: string;
}

// The vectors live in the Go module so they ship with it; resolve them from this file, not cwd.
const vectorsPath = fileURLToPath(
  new URL("../../../go/pqcratchet/testdata/challenge_v2_vectors.json", import.meta.url),
);
const { vectors } = JSON.parse(readFileSync(vectorsPath, "utf8")) as { vectors: Vector[] };

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const flip = (b: Uint8Array, bit: number) => {
  const c = b.slice();
  c[bit >> 3] ^= 1 << (bit & 7);
  return c;
};

describe("computeChallengeV2 vectors", () => {
  test("has at least 6 shared vectors", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(6);
  });

  test.each(vectors.map((v, i) => [i, v.note, v] as const))("matches vector %d (%s)", async (_i, _note, v) => {
    const client = fromHex(v.clientSigningPub);
    const cn = fromHex(v.clientNonce);
    const commit = await commitChallengeNonce(client, cn);
    expect(toHex(commit)).toBe(v.commit);
    await expect(verifyChallengeCommit(client, cn, fromHex(v.commit))).resolves.toBe(true);
    const pin = await computeChallengeV2(fromHex(v.serverSigningPub), client, cn, fromHex(v.serverNonce));
    expect(pin).toBe(v.pin);
    expect(pin).toMatch(/^[0-9]{6}$/);
  });
});

describe("commit-then-reveal primitives", () => {
  const key = new TextEncoder().encode("client key");
  const good = new Uint8Array(CHALLENGE_NONCE_SIZE);
  const badSizes = [0, CHALLENGE_NONCE_SIZE - 1, CHALLENGE_NONCE_SIZE + 1];

  test.each(badSizes)("rejects %d-byte nonces", async (n) => {
    const bad = new Uint8Array(n);
    await expect(commitChallengeNonce(key, bad)).rejects.toThrow();
    await expect(computeChallengeV2(key, key, bad, good)).rejects.toThrow();
    await expect(computeChallengeV2(key, key, good, bad)).rejects.toThrow();
    await expect(verifyChallengeCommit(key, bad, new Uint8Array(32))).resolves.toBe(false);
  });

  test("rejects wrong-size commits", async () => {
    const commit = await commitChallengeNonce(key, good);
    for (const c of [new Uint8Array(0), commit.slice(0, 31), Uint8Array.of(...commit, 0)]) {
      await expect(verifyChallengeCommit(key, good, c)).resolves.toBe(false);
    }
  });

  test("rejects a flipped bit in nonce, commit, or client key", async () => {
    const nonce = newChallengeNonce();
    const commit = await commitChallengeNonce(key, nonce);
    await expect(verifyChallengeCommit(key, nonce, commit)).resolves.toBe(true);
    for (const bit of [0, 7, 100, 255]) {
      await expect(verifyChallengeCommit(key, flip(nonce, bit), commit)).resolves.toBe(false);
      await expect(verifyChallengeCommit(key, nonce, flip(commit, bit))).resolves.toBe(false);
    }
    for (const bit of [0, 9, key.length * 8 - 1]) {
      await expect(verifyChallengeCommit(flip(key, bit), nonce, commit)).resolves.toBe(false);
    }
  });

  test("newChallengeNonce returns 32 fresh bytes", () => {
    const a = newChallengeNonce();
    const b = newChallengeNonce();
    expect(a.length).toBe(32);
    expect(b.length).toBe(32);
    expect(toHex(a)).not.toBe(toHex(b));
  });
});
