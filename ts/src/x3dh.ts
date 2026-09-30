/**
 * x3dh.ts — KEM-based X3DH key agreement.
 *
 * Alice (initiator) — authenticateA:
 *   (ct1, ss1) = KEM.Encap(SPK_B)
 *   (ct2, ss2) = KEM.Encap(IK_B.ex)
 *   EK_A       = KEM.GenerateKeyPair()
 *   [ct4, ss3  = KEM.Encap(OPK_B)]
 *   T  = transcript (see buildInitiatorTranscript)
 *   th = SHA-256(T)
 *   RK || XS = HKDF(IKM=0xFF×32 || ss1 || ss2 [|| ss3], salt=th, info="pqcratchet/v2/KEMInit", L=64)
 *   InitiatorSig = ML-DSA-65.Sign(IK_A.sig.sk, T)
 *
 * Bob (responder) — authenticateB:
 *   rebuild T from the received values and Bob's own keys
 *   verify InitiatorSig BEFORE decapsulating
 *   ss1 = KEM.Decap(SPK_B.sk, ct1)
 *   ss2 = KEM.Decap(IK_B.ex.sk, ct2)
 *   [ss3 = KEM.Decap(OPK_B.sk, ct4)]
 *   RK || XS = HKDF(IKM=0xFF×32 || ss1 || ss2 [|| ss3], salt=th, info="pqcratchet/v2/KEMInit", L=64)
 *
 * RK is the initial root key, XS the exporter secret, th the transcript hash.
 * The session context is opaque application data (at most
 * MAX_SESSION_CONTEXT_SIZE bytes). It is signed and mixed into every key.
 * The responder must check it against what it expects before acting.
 */

import {
  DSA_PUBLIC_KEY_SIZE, INFO_KEM_INIT, MAX_SESSION_CONTEXT_SIZE,
  PROTOCOL_ID, TRANSCRIPT_LABEL,
} from "./constants.js";
import { hkdf, concat, sha256, writeUint32BE } from "./crypto.js";
import { encapsulate, decapsulate, generateKEMKeyPair, HybridKEMKeyPair } from "./kem.js";
import { dsaSign, dsaVerify } from "./sign.js";
import { WIRE_VERSION } from "./wire.js";

export const ERR_SESSION_CONTEXT_TOO_LARGE = "pqcratchet: session context exceeds MAX_SESSION_CONTEXT_SIZE";

// ─── Types ───────────────────────────────────────────────────────────────────

/**
 * The responder's public keys as the initiator saw them in the bundle. They
 * are bound into the signed transcript, so a PreKeyMessage addressed to one
 * responder is rejected by any other.
 */
export interface ResponderKeys {
  signingPub: Uint8Array;       // IK_B.sig
  exchangePub: Uint8Array;      // IK_B.ex
  signedPreKeyPub: Uint8Array;  // SPK_B
}

export interface KEMInitiatorResult {
  rootKey: Uint8Array;
  exporterSecret: Uint8Array;
  transcriptHash: Uint8Array;
  sessionContext: Uint8Array;
  ephemeralKP: HybridKEMKeyPair;
  ct1: Uint8Array;
  ct2: Uint8Array;
  ct4: Uint8Array | null;
  initiatorSig: Uint8Array;
}

export interface KEMResponderResult {
  rootKey: Uint8Array;
  exporterSecret: Uint8Array;
  transcriptHash: Uint8Array;
}

// ─── AuthenticateA ───────────────────────────────────────────────────────────

export async function authenticateA(
  initiatorSigningKey: Uint8Array,
  initiatorExchangePub: Uint8Array,
  responder: ResponderKeys,
  remoteOneTimePreKeyPub: Uint8Array | null,
  sessionContext: Uint8Array = new Uint8Array(0),
  encapSeed?: Uint8Array, // for deterministic tests only
): Promise<KEMInitiatorResult> {
  checkContext(sessionContext);
  checkResponder(responder);

  // KEM1 = Encap(SPK_B) → ss1
  const { ciphertext: ct1, sharedSecret: ss1 } = await encapsulate(responder.signedPreKeyPub, encapSeed);

  // KEM2 = Encap(IK_B.ex) → ss2
  const seed2 = encapSeed ? encapSeed.slice(64) : undefined;
  const { ciphertext: ct2, sharedSecret: ss2 } = await encapsulate(responder.exchangePub, seed2);

  // Generate ephemeral keypair EK_A
  const seed3 = encapSeed ? encapSeed.slice(128, 224) : undefined;
  const ephemeralKP = generateKEMKeyPair(seed3);

  // Optional KEM3 = Encap(OPK_B) → ss3
  let ct4: Uint8Array | null = null;
  let ss3: Uint8Array | null = null;
  if (remoteOneTimePreKeyPub !== null) {
    const seed4 = encapSeed ? encapSeed.slice(224) : undefined;
    const r = await encapsulate(remoteOneTimePreKeyPub, seed4);
    ct4 = r.ciphertext;
    ss3 = r.sharedSecret;
  }

  const ctx = new Uint8Array(sessionContext);
  const transcript = await buildInitiatorTranscript(ctx, responder, initiatorExchangePub, ct1, ct2, ephemeralKP.publicKey, ct4);
  const transcriptHash = await sha256(transcript);
  const { rootKey, exporterSecret } = await deriveKEMRootKey(ss1, ss2, ss3, transcriptHash);
  const initiatorSig = dsaSign(initiatorSigningKey, transcript);

  return { rootKey, exporterSecret, transcriptHash, sessionContext: ctx, ephemeralKP, ct1, ct2, ct4, initiatorSig };
}

// ─── AuthenticateB ───────────────────────────────────────────────────────────

export async function authenticateB(
  identityExchangePriv: Uint8Array,
  signedPreKeyPriv: Uint8Array,
  oneTimePreKeyPriv: Uint8Array | null,
  responder: ResponderKeys,
  initiatorSigningPub: Uint8Array,
  initiatorExchangePub: Uint8Array,
  baseKey: Uint8Array,          // EK_A.pub
  ct1: Uint8Array,
  ct2: Uint8Array,
  ct4: Uint8Array | null,
  sessionContext: Uint8Array,
  initiatorSig: Uint8Array,
): Promise<KEMResponderResult> {
  checkContext(sessionContext);
  checkResponder(responder);

  // Verify initiator signature BEFORE decapsulating.
  // This prevents Bob's decapsulation from being used as a chosen-ciphertext oracle.
  const transcript = await buildInitiatorTranscript(sessionContext, responder, initiatorExchangePub, ct1, ct2, baseKey, ct4);
  if (!dsaVerify(initiatorSigningPub, transcript, initiatorSig)) {
    throw new Error("pqcratchet: invalid signature");
  }
  const transcriptHash = await sha256(transcript);

  // ss1 = Decap(SPK_B.sk, ct1)
  const ss1 = await decapsulate(signedPreKeyPriv, ct1);

  // ss2 = Decap(IK_B.ex.sk, ct2)
  const ss2 = await decapsulate(identityExchangePriv, ct2);

  // Optional ss3 = Decap(OPK_B.sk, ct4)
  let ss3: Uint8Array | null = null;
  if (oneTimePreKeyPriv !== null && ct4 !== null) {
    ss3 = await decapsulate(oneTimePreKeyPriv, ct4);
  } else if (oneTimePreKeyPriv !== null && ct4 === null) {
    throw new Error("pqcratchet: have OPK private key but initiator sent no CT4");
  } else if (oneTimePreKeyPriv === null && ct4 !== null) {
    throw new Error("pqcratchet: initiator sent CT4 but no OPK private key available");
  }

  const { rootKey, exporterSecret } = await deriveKEMRootKey(ss1, ss2, ss3, transcriptHash);
  return { rootKey, exporterSecret, transcriptHash };
}

// ─── Transcript ──────────────────────────────────────────────────────────────

/**
 * The byte string Alice signs and Bob verifies. Must match Go's
 * buildInitiatorTranscript exactly:
 *
 *   "pqcratchet/v2/X3DH"
 *   u8   WIRE_VERSION
 *   u32  len(PROTOCOL_ID) || PROTOCOL_ID
 *   u32  len(ctx)         || ctx
 *   [32] SHA-256(IK_B.sig)
 *   IK_B.ex || SPK_B
 *   IK_A.ex || CT1 || CT2 || EK_A.pub
 *   u8   hasCT4 [|| CT4]
 */
export async function buildInitiatorTranscript(
  sessionContext: Uint8Array,
  responder: ResponderKeys,
  initiatorExchangePub: Uint8Array,
  ct1: Uint8Array,
  ct2: Uint8Array,
  baseKey: Uint8Array,
  ct4: Uint8Array | null,
): Promise<Uint8Array> {
  const protocolId = new TextEncoder().encode(PROTOCOL_ID);
  const parts: Uint8Array[] = [
    TRANSCRIPT_LABEL,
    new Uint8Array([WIRE_VERSION]),
    writeUint32BE(protocolId.length), protocolId,
    writeUint32BE(sessionContext.length), sessionContext,
    await sha256(responder.signingPub),
    responder.exchangePub,
    responder.signedPreKeyPub,
    initiatorExchangePub, ct1, ct2, baseKey,
  ];
  if (ct4 !== null) parts.push(new Uint8Array([0x01]), ct4);
  else parts.push(new Uint8Array([0x00]));
  return concat(...parts);
}

// ─── Root key derivation ─────────────────────────────────────────────────────

async function deriveKEMRootKey(
  ss1: Uint8Array,
  ss2: Uint8Array,
  ss3: Uint8Array | null,
  transcriptHash: Uint8Array,
): Promise<{ rootKey: Uint8Array; exporterSecret: Uint8Array }> {
  if (ss1.length !== 32) throw new Error(`pqcratchet: x3dh ss1 must be 32 bytes, got ${ss1.length}`);
  if (ss2.length !== 32) throw new Error(`pqcratchet: x3dh ss2 must be 32 bytes, got ${ss2.length}`);
  if (ss3 !== null && ss3.length !== 32) throw new Error(`pqcratchet: x3dh ss3 must be 32 bytes, got ${ss3.length}`);
  if (transcriptHash.length !== 32) throw new Error(`pqcratchet: x3dh transcript hash must be 32 bytes, got ${transcriptHash.length}`);

  const domainSep = new Uint8Array(32).fill(0xFF);
  const parts: Uint8Array[] = [domainSep, ss1, ss2];
  if (ss3 !== null) parts.push(ss3);
  const keyMaterial = concat(...parts);

  // Salt is the transcript hash, so the keys depend on everything Alice signed.
  const out = await hkdf(keyMaterial, transcriptHash, INFO_KEM_INIT, 64);
  const rootKey = out.slice(0, 32);
  const exporterSecret = out.slice(32, 64);
  out.fill(0);
  return { rootKey, exporterSecret };
}

function checkContext(ctx: Uint8Array): void {
  if (ctx.length > MAX_SESSION_CONTEXT_SIZE) throw new Error(ERR_SESSION_CONTEXT_TOO_LARGE);
}

function checkResponder(r: ResponderKeys): void {
  if (r.signingPub.length !== DSA_PUBLIC_KEY_SIZE) {
    throw new Error(`pqcratchet: responder signing key must be ${DSA_PUBLIC_KEY_SIZE} bytes, got ${r.signingPub.length}`);
  }
}
