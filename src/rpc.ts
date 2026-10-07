// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * Public RPC contract for the Cofferdam Self attester Worker.
 *
 * This file is the source-of-truth for the wire shape consumers see
 * over a Cloudflare service binding. Consumer Workers (cofferdam-api)
 * MUST keep its local copy of this interface
 * byte-compatible with this file. A future shared `@cofferdam/types`
 * package will collapse the duplication.
 *
 * Why decimal strings for bigints?
 * Cloudflare Workers RPC serialises arguments via structuredClone,
 * which DOES support BigInt — but only when both Workers run on the
 * same compatibility date / runtime version. Using decimal strings
 * keeps the wire format agnostic to runtime tweaks and trivially
 * inspectable in `wrangler tail`.
 */

import type { Hex } from 'viem';

/** Request payload for `signBind`. */
export interface SignBindRequest {
  /**
   * Target `NullifierRegistry` address. Must equal the attester's
   * configured `NULLIFIER_REGISTRY_ADDRESS` — otherwise the call
   * rejects with `RegistryNotAllowed`.
   */
  readonly registry: Hex;

  /** Target account being bound (from the proof's USER_IDENTIFIER signal). */
  readonly account: Hex;

  /**
   * 21 public signals from the `vc_and_disclose` proof, encoded as
   * decimal strings (each up to 78 chars for a 256-bit field element).
   * Index layout per `contracts/v2/self/SelfPublicSignals.sol`.
   */
  readonly pubSignals: readonly string[];

  /**
   * Preimage of the proof's `userIdentifier` signal (index 20):
   * `abi.encodePacked(bytes32(SelfApp.chainID), bytes32(userId), userDefinedData)`.
   *
   * Required because signal 20 is a `ripemd160(sha256(...))` commitment, NOT
   * the raw account address. The attester recomputes it to fail fast, and
   * `NullifierRegistry.verifyAndBind` takes the same bytes and re-checks them
   * on-chain. Must be at least 64 bytes.
   */
  readonly userContextData: Hex;
}

/** Response from `signBind`. */
export interface SignBindResponse {
  /** Recovered signer address (must be in `SelfAttesterRegistry` allow-list). */
  readonly attesterAddress: Hex;

  /** Raw 32-byte hash that was signed (matches `NullifierRegistry.attesterMessageHash`). */
  readonly messageHash: Hex;

  /** 65-byte EIP-191 personal_sign signature, ready for `verifyAttesterSig`. */
  readonly signature: Hex;

  /** Echoed for caller-side audit. */
  readonly chainId: string;
  readonly registry: Hex;
  readonly account: Hex;

  /**
   * Echoed so the caller submits byte-identical bytes to `verifyAndBind`;
   * any divergence fails the on-chain commitment check.
   */
  readonly userContextData: Hex;
}

// ════════════════════════════════════════════════════════════════════
// signBindWithAttestation — staged Self bind path
//
// Same output as `signBind`, but the attester independently verifies a
// Self proving-enclave attestation before it will sign, instead of
// trusting the caller to have done so.
//
// ⚠️ TESTNET ONLY. The GCP Confidential Space attestation Self emits is
// a channel-binding credential minted during the TEE WebSocket
// handshake — before the proof exists. It attests "an allowlisted Self
// enclave image offered this ECDH public key", NOT "the nullifier in
// this request came from that enclave". Only the holder of the derived
// shared key can bridge those, and that holder is the mobile app.
//
// This method therefore reduces to "trust the app, but confirm it did
// talk to a real Self enclave". It exists to unblock end-to-end
// plumbing on Base Sepolia. The attester refuses to serve it when
// ENVIRONMENT=production; the mainnet gate is BIND_GATE_MODE=celo,
// which re-verifies the Groth16 proof against Self's Celo registry.
// ════════════════════════════════════════════════════════════════════

/** Request payload for `signBindWithAttestation`. */
export interface SignBindWithAttestationRequest extends SignBindRequest {
  /**
   * The raw GCP Confidential Space attestation JWT emitted by the Self
   * proving enclave, as a compact-serialisation string
   * (`header.payload.signature`).
   *
   * Sourced in the app from `selfClient.getProvingState().attestation`,
   * which Self stores as a `number[]` of UTF-8 bytes; the caller decodes
   * it to a string before sending.
   */
  readonly attestation: string;
}

/** Response from `signBindWithAttestation`. */
export interface SignBindWithAttestationResponse extends SignBindResponse {
  /**
   * The verified enclave image measurement (lowercase sha256 hex, no
   * `sha256:` prefix). Echoed so callers can record which Self enclave
   * build produced the proof, and alert on unexpected rotations.
   */
  readonly enclaveImageDigest: string;

  /**
   * Always `'attestation'` for this method. Present so a consumer
   * reading an audit record can tell which gate admitted the bind
   * without inferring it from the method name.
   */
  readonly gate: 'attestation';
}

// ════════════════════════════════════════════════════════════════════
// issueProverSession — Session-4 NEW
//
// The Cofferdam RN app calls this before posting an encrypted passport
// payload to Self.xyz's proving endpoint. The attester returns a
// short-lived JWT (HS256, 60-second TTL) that the caller verifies locally
// with the same JWT_SHARED_SECRET. This pairs the prove request to a
// specific account + registry combo and prevents replay.
//
// Production-hardening (Session 5+): migrate from HS256 + shared
// secret to Ed25519 / ES256 so the verifier only ever holds a public
// key, eliminating the (currently academic) attester-forgery surface.
// ════════════════════════════════════════════════════════════════════

/** Request payload for `issueProverSession`. */
export interface IssueProverSessionRequest {
  /**
   * The AA account address that will receive the bind. Surfaced in the
   * JWT `sub` claim; the prover echoes it back as a header so the
   * follow-up `signBind` call uses the same value (defence against
   * UI-side account confusion).
   */
  readonly account: Hex;

  /**
   * Target `NullifierRegistry` contract address. Surfaced as a custom
   * `registry` claim. The attester refuses to issue a session for
   * any registry other than the one in `NULLIFIER_REGISTRY_ADDRESS`
   * — same allowlist as `signBind`.
   */
  readonly registry: Hex;
}

/** Response from `issueProverSession`. */
export interface IssueProverSessionResponse {
  /**
   * The JWT to pass as `Authorization: Bearer <jwt>` to the prover.
   * HS256-signed using JWT_SHARED_SECRET. TTL = 60 seconds from
   * issuance. Claims:
   *
   *   iss: "cofferdam-attester"
   *   aud: "cofferdam-attester"
   *   sub: <account>          // hex address
   *   registry: <registry>    // hex address, custom claim
   *   iat / nbf / exp
   */
  readonly jwt: string;

  /** Expiry timestamp (seconds since epoch). Echoes the JWT `exp` claim. */
  readonly exp: number;

  /** Echoed for caller-side audit. */
  readonly account: Hex;
  readonly registry: Hex;
}

/**
 * The full RPC surface this Worker exposes. Add new methods here +
 * to `CofferdamAttester` in `index.ts`. Consumers see this as their
 * binding's static type when they declare `Service<AttesterRpc>`.
 *
 * `extends Rpc.WorkerEntrypointBranded` is required to satisfy the
 * generic constraint on Cloudflare's `Service<T>` helper. The brand
 * is purely structural at type-check time — it adds nothing at
 * runtime.
 */
export interface AttesterRpc extends Rpc.WorkerEntrypointBranded {
  signBind(req: SignBindRequest): Promise<SignBindResponse>;
  signBindWithAttestation(
    req: SignBindWithAttestationRequest,
  ): Promise<SignBindWithAttestationResponse>;
  issueProverSession(req: IssueProverSessionRequest): Promise<IssueProverSessionResponse>;
}
