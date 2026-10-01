/**
 * session_binding.test.ts — session context, responder binding, exporter,
 * and wire version 0x02. Mirrors go/pqcratchet/session_binding_test.go.
 */

import {
  generateIdentity, createSessionInitiator, createSessionResponder,
  Identity, PreKeyBundle, PreKeyMessage,
  marshalPreKeyMessageWire, unmarshalPreKeyMessageWire, unmarshalSignedMessage, unmarshalMessageProtocol,
  DSA_PUBLIC_KEY_SIZE, DSA_SIGNATURE_SIZE, HYBRID_CIPHERTEXT_SIZE,
  WIRE_VERSION, NO_ONE_TIME_PRE_KEY, MAX_SESSION_CONTEXT_SIZE, HYBRID_PUBLIC_KEY_SIZE,
  ERR_SESSION_CONTEXT_TOO_LARGE, ERR_EXPORTER_LENGTH, Session,
} from "../index.js";

const enc = (s: string) => new TextEncoder().encode(s);

function bundleFor(id: Identity, withOPK = true): PreKeyBundle {
  return {
    registrationId: id.id,
    identitySigningPub: id.signingKey.publicKey,
    identityExchangePub: id.exchangeKey.publicKey,
    signedPreKeyPub: id.signedPreKeys[0].publicKey,
    signedPreKeyIndex: 0,
    signedPreKeySig: id.signedPreKeySigs[0],
    oneTimePreKeyPub: withOPK ? id.preKeys[0]!.publicKey : null,
    oneTimePreKeyIndex: withOPK ? 0 : -1,
  };
}

function toWire(m: PreKeyMessage): Uint8Array {
  return marshalPreKeyMessageWire({
    registrationID: m.registrationId,
    signedPreKeyIndex: m.signedPreKeyIndex,
    oneTimePreKeyIndex: m.oneTimePreKeyIndex < 0 ? NO_ONE_TIME_PRE_KEY : m.oneTimePreKeyIndex,
    sessionContext: m.sessionContext ?? new Uint8Array(0),
    signingPub: m.identitySigningPub,
    exchangeKeySig: m.exchangeKeySig,
    exchangePub: m.identityExchangePub,
    baseKey: m.baseKey,
    ct1: m.ct1, ct2: m.ct2, ct4: m.ct4,
    initiatorSig: m.initiatorSig,
    signedMessageBytes: new Uint8Array(0),
  });
}

function fromWire(b: Uint8Array): PreKeyMessage {
  const w = unmarshalPreKeyMessageWire(b);
  return {
    registrationId: w.registrationID,
    sessionContext: w.sessionContext,
    identitySigningPub: w.signingPub,
    identityExchangePub: w.exchangePub,
    exchangeKeySig: w.exchangeKeySig,
    baseKey: w.baseKey,
    ct1: w.ct1, ct2: w.ct2, ct4: w.ct4,
    initiatorSig: w.initiatorSig,
    signedPreKeyIndex: w.signedPreKeyIndex,
    oneTimePreKeyIndex: w.oneTimePreKeyIndex === NO_ONE_TIME_PRE_KEY ? -1 : w.oneTimePreKeyIndex,
  };
}

async function establish(ctx: Uint8Array) {
  const alice = await generateIdentity(1, 1, 1);
  const bob = await generateIdentity(2, 1, 1);
  const { session: aliceSess, preKeyMessage } = await createSessionInitiator(alice, bundleFor(bob), ctx);
  const pkmBytes = toWire(preKeyMessage);
  const bobSess = await createSessionResponder(bob, fromWire(pkmBytes));
  return { alice, bob, aliceSess, bobSess, pkmBytes };
}

async function roundTrip(from: Session, to: Session, text: string) {
  const pt = await to.open(await from.seal(enc(text)));
  expect(new TextDecoder().decode(pt)).toBe(text);
}

// Offset of the session context in a marshalled PKM: version + 3×u32 + ctxLen.
const CTX_OFFSET = 1 + 4 + 4 + 4 + 4;

test("session context is bound and delivered", async () => {
  const ctx = enc('{"sid":"s_123","origin":"https://payroll.example"}');
  const { aliceSess, bobSess } = await establish(ctx);
  expect(aliceSess.sessionContext).toEqual(ctx);
  expect(bobSess.sessionContext).toEqual(ctx);
  expect(aliceSess.transcriptHash.length).toBe(32);
  expect(aliceSess.transcriptHash).toEqual(bobSess.transcriptHash);
  await roundTrip(aliceSess, bobSess, "hello");
  await roundTrip(bobSess, aliceSess, "reply");
});

test("tampered session context is rejected without consuming the OPK", async () => {
  const ctx = enc("sid=s_123;origin=https://a.example");
  const alice = await generateIdentity(1, 1, 0);
  const bob = await generateIdentity(2, 1, 1);
  const { preKeyMessage } = await createSessionInitiator(alice, bundleFor(bob), ctx);
  const pkmBytes = toWire(preKeyMessage);
  const tampered = new Uint8Array(pkmBytes);
  tampered[CTX_OFFSET + ctx.length - 1] ^= 0x01;
  await expect(createSessionResponder(bob, fromWire(tampered))).rejects.toThrow("invalid signature");
  expect(bob.preKeys[0]).not.toBeNull();
  await createSessionResponder(bob, fromWire(pkmBytes));
});

test("rewritten one-time pre-key index is rejected and no OPK is consumed", async () => {
  const alice = await generateIdentity(1, 1, 0);
  const bob = await generateIdentity(2, 1, 3);
  const { preKeyMessage } = await createSessionInitiator(alice, bundleFor(bob));
  for (const idx of [1, 2]) {
    await expect(createSessionResponder(bob, { ...preKeyMessage, oneTimePreKeyIndex: idx }))
      .rejects.toThrow("invalid signature");
  }
  expect(bob.preKeys.every(k => k !== null)).toBe(true);
  await createSessionResponder(bob, preKeyMessage);
  expect(bob.preKeys[0]).toBeNull();
  expect(bob.preKeys[1]).not.toBeNull();
  expect(bob.preKeys[2]).not.toBeNull();
});

test("rewritten signed pre-key index is rejected", async () => {
  const alice = await generateIdentity(1, 1, 0);
  const bob = await generateIdentity(2, 2, 0);
  const { preKeyMessage } = await createSessionInitiator(alice, bundleFor(bob, false));
  await expect(createSessionResponder(bob, { ...preKeyMessage, signedPreKeyIndex: 1 }))
    .rejects.toThrow("invalid signature");
});

test("wrong-size transcript fields are rejected", async () => {
  const alice = await generateIdentity(1, 1, 0);
  const bob = await generateIdentity(2, 1, 0);
  const { preKeyMessage } = await createSessionInitiator(alice, bundleFor(bob, false));
  await expect(createSessionResponder(bob, { ...preKeyMessage, ct1: preKeyMessage.ct1.slice(1) }))
    .rejects.toThrow("CT1 must be");
  await expect(createSessionResponder(bob, { ...preKeyMessage, baseKey: new Uint8Array(10) }))
    .rejects.toThrow("base key must be");
});

test("non-canonical flag bytes are rejected", async () => {
  const { aliceSess, pkmBytes } = await establish(new Uint8Array(0));
  const hasCT4 = CTX_OFFSET + DSA_PUBLIC_KEY_SIZE + DSA_SIGNATURE_SIZE + 2 * HYBRID_PUBLIC_KEY_SIZE + 2 * HYBRID_CIPHERTEXT_SIZE;
  expect(pkmBytes[hasCT4]).toBe(0x01);
  const pkm = new Uint8Array(pkmBytes);
  pkm[hasCT4] = 0x02;
  expect(() => unmarshalPreKeyMessageWire(pkm)).toThrow("hasCT4 must be 0 or 1");

  const sm = unmarshalSignedMessage(await aliceSess.seal(enc("x")));
  const inner = new Uint8Array(sm.messageRaw);
  inner[4 + HYBRID_PUBLIC_KEY_SIZE] = 0x02;
  expect(() => unmarshalMessageProtocol(inner)).toThrow("hasRatchetCT must be 0 or 1");
});

test("returned PreKeyMessage context is a copy", async () => {
  const alice = await generateIdentity(1, 1, 0);
  const bob = await generateIdentity(2, 1, 0);
  const ctx = enc("sid=1");
  const { session, preKeyMessage } = await createSessionInitiator(alice, bundleFor(bob, false), ctx);
  preKeyMessage.sessionContext![0] ^= 0xff;
  expect(session.sessionContext).toEqual(ctx);
});

test("replaced or stripped session context is rejected", async () => {
  const alice = await generateIdentity(1, 1, 0);
  const bob = await generateIdentity(2, 1, 0);
  const { preKeyMessage } = await createSessionInitiator(alice, bundleFor(bob, false), enc("origin=https://a.example"));
  await expect(createSessionResponder(bob, { ...preKeyMessage, sessionContext: enc("origin=https://evil.example") }))
    .rejects.toThrow("invalid signature");
  await expect(createSessionResponder(bob, { ...preKeyMessage, sessionContext: undefined }))
    .rejects.toThrow("invalid signature");
});

test("PreKeyMessage for one responder is rejected by another", async () => {
  const alice = await generateIdentity(1, 1, 0);
  const bob = await generateIdentity(2, 1, 1);
  const carol = await generateIdentity(3, 1, 1);
  const { preKeyMessage } = await createSessionInitiator(alice, bundleFor(bob));
  await expect(createSessionResponder(carol, preKeyMessage)).rejects.toThrow("invalid signature");
  expect(carol.preKeys[0]).not.toBeNull();
});

test("session context size limit", async () => {
  const alice = await generateIdentity(1, 1, 0);
  const bob = await generateIdentity(2, 1, 0);
  const big = new Uint8Array(MAX_SESSION_CONTEXT_SIZE + 1);
  await expect(createSessionInitiator(alice, bundleFor(bob, false), big)).rejects.toThrow(ERR_SESSION_CONTEXT_TOO_LARGE);

  const { preKeyMessage } = await createSessionInitiator(alice, bundleFor(bob, false));
  const b = toWire(preKeyMessage);
  b.set([0x7f, 0xff, 0xff, 0xff], CTX_OFFSET - 4);
  expect(() => unmarshalPreKeyMessageWire(b)).toThrow("session context exceeds");

  await createSessionInitiator(alice, bundleFor(bob, false), new Uint8Array(MAX_SESSION_CONTEXT_SIZE));
});

test("version 0x01 frames are rejected", async () => {
  expect(WIRE_VERSION).toBe(0x02);
  const { aliceSess, pkmBytes } = await establish(new Uint8Array(0));
  const pkm = new Uint8Array(pkmBytes);
  pkm[0] = 0x01;
  expect(() => unmarshalPreKeyMessageWire(pkm)).toThrow("unsupported version");
  const wire = await aliceSess.seal(enc("x"));
  wire[0] = 0x01;
  expect(() => unmarshalSignedMessage(wire)).toThrow("unsupported version");
});

test("AD ends with the transcript hash", async () => {
  const { aliceSess, bobSess } = await establish(enc("ctx"));
  expect(aliceSess.ad.length).toBe(2 * HYBRID_PUBLIC_KEY_SIZE + 32);
  expect(aliceSess.ad).toEqual(bobSess.ad);
  expect(aliceSess.ad.slice(2 * HYBRID_PUBLIC_KEY_SIZE)).toEqual(aliceSess.transcriptHash);
});

test("exportKeyingMaterial", async () => {
  const { aliceSess, bobSess } = await establish(enc("sid=s_1"));
  const label = "goodkey approval";
  const op = enc("op=x509/sign");

  const a = await aliceSess.exportKeyingMaterial(label, op, 32);
  expect(await bobSess.exportKeyingMaterial(label, op, 32)).toEqual(a);
  expect(await aliceSess.exportKeyingMaterial("other", op, 32)).not.toEqual(a);
  expect(await aliceSess.exportKeyingMaterial(label, enc("op=unwrap"), 32)).not.toEqual(a);
  expect(await aliceSess.exportKeyingMaterial("ab", enc("c"), 32))
    .not.toEqual(await aliceSess.exportKeyingMaterial("a", enc("bc"), 32));

  await roundTrip(aliceSess, bobSess, "one");
  await roundTrip(bobSess, aliceSess, "two");
  await roundTrip(aliceSess, bobSess, "three");
  expect(await bobSess.exportKeyingMaterial(label, op, 32)).toEqual(a);

  const other = await establish(enc("sid=s_1"));
  expect(await other.aliceSess.exportKeyingMaterial(label, op, 32)).not.toEqual(a);

  const long = await aliceSess.exportKeyingMaterial(label, op, 64);
  expect(long.slice(0, 32)).toEqual(a);

  for (const n of [0, -1, 255 * 32 + 1, 1.5]) {
    await expect(aliceSess.exportKeyingMaterial("x", new Uint8Array(0), n)).rejects.toThrow(ERR_EXPORTER_LENGTH);
  }
  expect((await aliceSess.exportKeyingMaterial("x", new Uint8Array(0), 255 * 32)).length).toBe(255 * 32);
});

test("sessions with the same identities and empty context have distinct ADs", async () => {
  const alice = await generateIdentity(1, 1, 0);
  const bob = await generateIdentity(2, 1, 0);
  const s1 = await createSessionInitiator(alice, bundleFor(bob, false));
  const s2 = await createSessionInitiator(alice, bundleFor(bob, false));
  expect(s1.session.ad).not.toEqual(s2.session.ad);
});
