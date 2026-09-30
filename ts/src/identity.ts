/**
 * identity.ts — Identity and session bootstrap.
 */

import { generateKEMKeyPair, HybridKEMKeyPair, zeroKEMKeyPair } from "./kem.js";
import { generateDSAKeyPair, DSAKeyPair, dsaSign, dsaVerify } from "./sign.js";
import { authenticateA, authenticateB, KEMInitiatorResult, KEMResponderResult } from "./x3dh.js";
import { Session } from "./session.js";
import { concat } from "./crypto.js";

// ─── Identity ────────────────────────────────────────────────────────────────

export interface Identity {
  id: number;
  signingKey: DSAKeyPair;
  exchangeKey: HybridKEMKeyPair;
  exchangeKeySignature: Uint8Array; // Sig(signingKey, exchangeKey.publicKey)
  signedPreKeys: HybridKEMKeyPair[];
  signedPreKeySigs: Uint8Array[];
  preKeys: (HybridKEMKeyPair | null)[];
}

export interface PreKeyBundle {
  registrationId: number;
  identitySigningPub: Uint8Array;
  identityExchangePub: Uint8Array;
  signedPreKeyPub: Uint8Array;
  signedPreKeyIndex: number;
  signedPreKeySig: Uint8Array;
  oneTimePreKeyPub: Uint8Array | null;
  oneTimePreKeyIndex: number;
}

export interface PreKeyMessage {
  registrationId: number;
  /**
   * Application context the initiator signed (may be empty). Authenticated by
   * initiatorSig; the responder must still check it against what it expects.
   */
  sessionContext?: Uint8Array;
  identitySigningPub: Uint8Array;
  identityExchangePub: Uint8Array;
  exchangeKeySig: Uint8Array;
  baseKey: Uint8Array;  // EK_A.pub
  ct1: Uint8Array;
  ct2: Uint8Array;
  ct4: Uint8Array | null;
  initiatorSig: Uint8Array;
  signedPreKeyIndex: number;
  oneTimePreKeyIndex: number;
}

// ─── Generate identity ───────────────────────────────────────────────────────

export async function generateIdentity(
  id: number,
  numSignedPreKeys: number,
  numOneTimePreKeys: number,
): Promise<Identity> {
  const signingKey = generateDSAKeyPair();
  const exchangeKey = generateKEMKeyPair();

  // Sign the exchange public key with the signing key
  const exchangeKeySignature = dsaSign(signingKey.privateKey, exchangeKey.publicKey);

  const signedPreKeys: HybridKEMKeyPair[] = [];
  const signedPreKeySigs: Uint8Array[] = [];
  for (let i = 0; i < numSignedPreKeys; i++) {
    const kp = generateKEMKeyPair();
    const sig = dsaSign(signingKey.privateKey, kp.publicKey);
    signedPreKeys.push(kp);
    signedPreKeySigs.push(sig);
  }

  const preKeys: HybridKEMKeyPair[] = [];
  for (let i = 0; i < numOneTimePreKeys; i++) {
    preKeys.push(generateKEMKeyPair());
  }

  return {
    id,
    signingKey,
    exchangeKey,
    exchangeKeySignature,
    signedPreKeys,
    signedPreKeySigs,
    preKeys,
  };
}

// ─── Session creation ────────────────────────────────────────────────────────

export interface InitiatorSessionResult {
  session: Session;
  preKeyMessage: PreKeyMessage;
}

/**
 * createSessionInitiator creates a session from Alice's perspective.
 * Validates the bundle signatures before proceeding.
 *
 * sessionContext is bound into the signed X3DH transcript and every derived
 * key, and travels to the responder in the PreKeyMessage. Deployments that
 * route sessions through an intermediary should put the session id and
 * origin in it. At most MAX_SESSION_CONTEXT_SIZE bytes.
 */
export async function createSessionInitiator(
  initiatorIdentity: Identity,
  bundle: PreKeyBundle,
  sessionContext: Uint8Array = new Uint8Array(0),
): Promise<InitiatorSessionResult> {
  // Verify signed pre-key signature
  if (!dsaVerify(bundle.identitySigningPub, bundle.signedPreKeyPub, bundle.signedPreKeySig)) {
    throw new Error("pqcratchet: invalid signed pre-key signature");
  }

  const x3dhResult = await authenticateA(
    initiatorIdentity.signingKey.privateKey,
    initiatorIdentity.exchangeKey.publicKey,
    {
      signingPub: bundle.identitySigningPub,
      exchangePub: bundle.identityExchangePub,
      signedPreKeyPub: bundle.signedPreKeyPub,
    },
    bundle.oneTimePreKeyPub,
    sessionContext,
  );

  // AD = Encode(IK_A.ex) || Encode(IK_B.ex) || transcriptHash
  const ad = concat(initiatorIdentity.exchangeKey.publicKey, bundle.identityExchangePub, x3dhResult.transcriptHash);

  // Session: Alice starts with ephemeral keypair as ratchet key
  const session = new Session(
    x3dhResult.rootKey,
    x3dhResult.ephemeralKP,
    ad,
    initiatorIdentity.signingKey.publicKey,
    bundle.identitySigningPub,
    x3dhResult.transcriptHash,
    x3dhResult.sessionContext,
    x3dhResult.exporterSecret,
  );

  // Initiator needs to set the remote ratchet key so the first send can encapsulate.
  // Alice's initial remote ratchet key is Bob's signed pre-key (not his exchange key).
  // This matches Go: CurrentStep.RemoteRatchetKey = bundle.SignedPreKeyPub.
  // Bob's initial ratchet KP is also this signed pre-key, so Alice's encapsulation
  // against it produces the shared secret Bob decapsulates with his SPK private key.
  session.currentStep = {
    remoteRatchetKey: bundle.signedPreKeyPub, // Bob's SPK = initial remote ratchet key
    epochRatchetCT: null,
    sendingChain: null,
    receivingChain: null,
  };

  const preKeyMessage: PreKeyMessage = {
    registrationId: bundle.registrationId,
    identitySigningPub: initiatorIdentity.signingKey.publicKey,
    identityExchangePub: initiatorIdentity.exchangeKey.publicKey,
    exchangeKeySig: initiatorIdentity.exchangeKeySignature,
    baseKey: x3dhResult.ephemeralKP.publicKey,
    ct1: x3dhResult.ct1,
    ct2: x3dhResult.ct2,
    ct4: x3dhResult.ct4,
    initiatorSig: x3dhResult.initiatorSig,
    sessionContext: x3dhResult.sessionContext,
    signedPreKeyIndex: bundle.signedPreKeyIndex,
    oneTimePreKeyIndex: bundle.oneTimePreKeyIndex,
  };

  return { session, preKeyMessage };
}

/**
 * createSessionResponder creates a session from Bob's perspective.
 * Verifies the initiator's exchange key signature and transcript signature.
 *
 * The session context in msg is authenticated by the initiator's signature,
 * which proves only that the initiator asserted it. Callers MUST compare
 * session.sessionContext with the context they expect before acting.
 */
export async function createSessionResponder(
  responderIdentity: Identity,
  msg: PreKeyMessage,
): Promise<Session> {
  // Verify Alice's exchange key signature
  if (!dsaVerify(msg.identitySigningPub, msg.identityExchangePub, msg.exchangeKeySig)) {
    throw new Error("pqcratchet: invalid exchange key signature");
  }

  if (msg.signedPreKeyIndex >= responderIdentity.signedPreKeys.length) {
    throw new Error(`pqcratchet: signed pre-key ${msg.signedPreKeyIndex} not found`);
  }

  // Handle OPK — nil slot before auth, restore on failure
  let oneTimePreKeyPriv: Uint8Array | null = null;
  let oneTimePreKeyKP: HybridKEMKeyPair | null = null;
  let oneTimePreKeyIndex = -1;

  if (msg.oneTimePreKeyIndex >= 0 && msg.oneTimePreKeyIndex < responderIdentity.preKeys.length) {
    const kp = responderIdentity.preKeys[msg.oneTimePreKeyIndex];
    if (kp !== null) {
      oneTimePreKeyPriv = kp.privateKey;
      oneTimePreKeyKP = kp;
      oneTimePreKeyIndex = msg.oneTimePreKeyIndex;
      responderIdentity.preKeys[msg.oneTimePreKeyIndex] = null; // nil slot
    }
  }

  const signedPreKP = responderIdentity.signedPreKeys[msg.signedPreKeyIndex];

  let x3dh: KEMResponderResult;
  try {
    x3dh = await authenticateB(
      responderIdentity.exchangeKey.privateKey,
      signedPreKP.privateKey,
      oneTimePreKeyPriv,
      {
        signingPub: responderIdentity.signingKey.publicKey,
        exchangePub: responderIdentity.exchangeKey.publicKey,
        signedPreKeyPub: signedPreKP.publicKey,
      },
      msg.identitySigningPub,
      msg.identityExchangePub,
      msg.baseKey,
      msg.ct1,
      msg.ct2,
      msg.ct4,
      msg.sessionContext ?? new Uint8Array(0),
      msg.initiatorSig,
    );
  } catch (e) {
    // Restore OPK slot on auth failure
    if (oneTimePreKeyIndex >= 0 && oneTimePreKeyKP !== null) {
      responderIdentity.preKeys[oneTimePreKeyIndex] = oneTimePreKeyKP;
    }
    throw e;
  }

  // Zero OPK after successful auth
  if (oneTimePreKeyKP !== null) zeroKEMKeyPair(oneTimePreKeyKP);

  // AD = Encode(IK_A.ex) || Encode(IK_B.ex) || transcriptHash
  const ad = concat(msg.identityExchangePub, responderIdentity.exchangeKey.publicKey, x3dh.transcriptHash);

  // Bob's initial ratchet keypair is the signed pre-key used in X3DH.
  // Alice encapsulates against this key to derive the first receiving chain.
  // This matches Go: RatchetKP = signedPreKP (not exchangeKey).
  // (signedPreKP was already declared above for authenticateB)

  const session = new Session(
    x3dh.rootKey,
    signedPreKP, // Bob's initial ratchet KP = the signed pre-key used in X3DH
    ad,
    msg.identitySigningPub,
    responderIdentity.signingKey.publicKey,
    x3dh.transcriptHash,
    new Uint8Array(msg.sessionContext ?? new Uint8Array(0)),
    x3dh.exporterSecret,
  );

  // Bob's first receive epoch uses Alice's base key (EK_A) as the remote ratchet key
  session.currentStep = {
    remoteRatchetKey: msg.baseKey,
    epochRatchetCT: null,
    sendingChain: null,
    receivingChain: null,
  };

  return session;
}
