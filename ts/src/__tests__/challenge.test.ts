/**
 * challenge.test.ts — checks computeChallenge against the shared vectors in go/pqcratchet/testdata/.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { computeChallenge } from "../index.js";

interface Vector {
  serverSigningPub: string;
  clientSigningPub: string;
  pin: string;
}

// The vectors live in the Go module so they ship with it; resolve them from this file, not cwd.
const vectorsPath = fileURLToPath(
  new URL("../../../go/pqcratchet/testdata/challenge_vectors.json", import.meta.url),
);
const { vectors } = JSON.parse(readFileSync(vectorsPath, "utf8")) as { vectors: Vector[] };

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));

describe("computeChallenge", () => {
  test("has at least 6 shared vectors", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(6);
  });

  test.each(vectors.map((v, i) => [i, v] as const))("matches vector %d", async (_i, v) => {
    const pin = await computeChallenge(fromHex(v.serverSigningPub), fromHex(v.clientSigningPub));
    expect(pin).toBe(v.pin);
    expect(pin).toMatch(/^[0-9]{6}$/);
  });
});
