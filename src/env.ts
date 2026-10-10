// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * Typed environment bindings for the Cofferdam Self attester Worker.
 *
 * Mirrors the `vars` and secrets declared in `wrangler.jsonc`. This Worker
 * has one job (gate and sign bind messages), zero resource bindings
 * (KV/R2/D1/services) and exactly one egress: read-only JSON-RPC to Celo for
 * the bind gate. Adding a binding or an egress here widens the blast radius
 * of the signing key — audit before doing so.
 */
export interface Env {
  // ── vars ────────────────────────────────────────────────────────

  /** 'development' | 'staging' | 'production'. Logged with every audit line. */
  ENVIRONMENT: 'development' | 'staging' | 'production';

  /**
   * Base chain id as a decimal string: Base Sepolia `84532`, Base mainnet
   * `8453`. Part of the signed preimage. A mainnet attester is a separate
   * Worker deploy, never a second value on this one.
   */
  BASE_CHAIN_ID: string;

  /**
   * EIP-55 address of the sole `NullifierRegistry` this attester signs for.
   * Must equal `SEPOLIA_DEPLOYMENTS.NullifierRegistry` in
   * `cofferdam-api/src/chain/deployments.ts`.
   */
  NULLIFIER_REGISTRY_ADDRESS: string;

  /**
   * JSON-RPC endpoint for Celo, the chain Self anchors its registries on.
   * Public `https://forno.celo.org` is fine; if you move to a keyed provider,
   * delete this var and set a secret of the same name instead.
   */
  CELO_RPC_URL: string;

  /**
   * Chain id `CELO_RPC_URL` must report (mainnet `42220`). Also the
   * `SelfApp.chainID` the app declares, which `NullifierRegistry.selfDestChainId`
   * pins immutably — the attester refuses a proof whose `userContextData`
   * names any other destination chain.
   */
  SELF_CELO_CHAIN_ID: string;

  /** Self `IdentityVerificationHubImplV2` proxy on Celo. */
  SELF_HUB_ADDRESS: string;

  /**
   * Self `IdentityRegistryImplV1` proxy for E_PASSPORT on Celo. The gate
   * cross-checks `hub.registry(E_PASSPORT)` against this pin and refuses on
   * mismatch, so a Self-side registry migration fails loudly.
   */
  SELF_PASSPORT_REGISTRY_ADDRESS: string;

  // ── secrets (set via `wrangler secret put NAME`) ────────────────

  /**
   * 0x-prefixed 32-byte secp256k1 private key. Its address must be
   * allow-listed in `SelfAttesterRegistry`, otherwise on-chain
   * `verifyAttesterSig` rejects every signature this Worker produces.
   *
   * Never log, persist or echo this value. Read once per request to derive
   * a viem account, then dropped.
   */
  ATTESTER_PRIVATE_KEY: string;
}
