// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * Public RPC contract for the Cofferdam Self attester Worker.
 *
 * This file is the source of truth for the wire shape consumers see over a
 * Cloudflare service binding. `cofferdam-api/src/services/attester.ts` keeps
 * a byte-compatible copy; update both in the same change.
 *
 * Why decimal strings for bigints? Workers RPC serialises arguments via
 * structuredClone, which supports BigInt only when both Workers run the same
 * runtime version. Decimal strings keep the wire format runtime-agnostic and
 * readable in `wrangler tail`.
 */

import type { Hex } from 'viem';

/** Request payload for `signBind`. */
export interface SignBindRequest {
  /**
   * Target `NullifierRegistry` address. Must equal the attester's pinned
   * `NULLIFIER_REGISTRY_ADDRESS`, otherwise `REGISTRY_NOT_ALLOWED`.
   */
  readonly registry: Hex;

  /** Account being bound; must be the user id embedded in `userContextData`. */
  readonly account: Hex;

  /**
   * The 21 public signals of the `vc_and_disclose` (E_PASSPORT) proof as
   * decimal strings. Index layout per `celoGate.ts` `PASSPORT_DISCLOSE_INDEX`.
   */
  readonly pubSignals: readonly string[];

  /**
   * Preimage of the proof's `userIdentifier` signal (index 20):
   * `abi.encodePacked(bytes32(SelfApp.chainID), bytes32(userId), userDefinedData)`,
   * 0x-prefixed, at least 64 bytes. Signal 20 is `ripemd160(sha256(...))` of
   * these bytes, not the raw address, so the attester needs the preimage to
   * tie the proof to `account`; `verifyAndBind` takes the same bytes.
   */
  readonly userContextData: Hex;
}

/** What the Celo gate established before the signature was produced. */
export interface CeloGateReceipt {
  /** Celo chain id the gate read from (`42220`). */
  readonly chainId: string;
  /** Self's E_PASSPORT identity registry the roots were checked against. */
  readonly registry: Hex;
  /** `pubSignals[9]`, confirmed as a root Self published. */
  readonly merkleRoot: string;
  /** ISO `YYYY-MM-DD` decoded from the proof's date signals. */
  readonly proofDate: string;
}

/** Response from `signBind`. */
export interface SignBindResponse {
  /** Recovered signer address (must be allow-listed in `SelfAttesterRegistry`). */
  readonly attesterAddress: Hex;

  /** The 32-byte hash that was signed (equals `NullifierRegistry.attesterMessageHash`). */
  readonly messageHash: Hex;

  /** 65-byte EIP-191 personal_sign signature, ready for `verifyAttesterSig`. */
  readonly signature: Hex;

  /** Echoed for caller-side audit. */
  readonly chainId: string;
  readonly registry: Hex;
  readonly account: Hex;

  /** Echoed so the caller submits byte-identical bytes to `verifyAndBind`. */
  readonly userContextData: Hex;

  /** The evidence class that admitted this bind. Always `celo` (decision 0004). */
  readonly gate: 'celo';

  /** Celo-side facts the signature rests on. */
  readonly celo: CeloGateReceipt;
}

/**
 * The full RPC surface. `extends Rpc.WorkerEntrypointBranded` satisfies the
 * generic constraint on Cloudflare's `Service<T>` helper; the brand is purely
 * structural at type-check time.
 */
export interface AttesterRpc extends Rpc.WorkerEntrypointBranded {
  signBind(req: SignBindRequest): Promise<SignBindResponse>;
}
