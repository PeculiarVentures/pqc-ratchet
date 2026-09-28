/**
 * challenge.test.ts — checks computeChallenge against the shared vectors in testdata/.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { computeChallenge } from "../index.js";

interface Vector {
  serverSigningPub: string;
  clientSigningPub: string;
  pin: string;
}

// npm test runs from ts/, so the repo-root testdata/ is one level up.
const { vectors } = JSON.parse(
  readFileSync(resolve(process.cwd(), "../testdata/challenge_vectors.json"), "utf8"),
) as { vectors: Vector[] };

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
