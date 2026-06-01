// Copyright (c) 2026 OffshoreSync LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Public RPC contract for the Cofferdam Self attester Worker.
 *
 * This file is the source-of-truth for the wire shape consumers see
 * over a Cloudflare service binding. Consumer Workers (cofferdam-api,
 * cofferdam-prover) MUST keep their local copy of this interface
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
}
