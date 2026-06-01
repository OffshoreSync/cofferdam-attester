/**
 * Typed environment bindings for the Cofferdam Self attester Worker.
 *
 * Mirrors the `vars` and secrets declared in `wrangler.jsonc`. Kept
 * deliberately small — this Worker has one job (sign bind messages)
 * and zero external resource bindings (KV/R2/D1/services). Adding a
 * binding here without auditing the implications on the attester
 * blast radius is a security regression.
 */
export interface Env {
  // ── vars ────────────────────────────────────────────────────────

  /** 'development' | 'staging' | 'production' — gate-keeps logging verbosity. */
  ENVIRONMENT: 'development' | 'staging' | 'production';

  /**
   * ZKSync Era Sepolia chain id, as a decimal string ('300').
   * Hardcoded into the message-hash preimage; the attester rejects
   * sign requests whose target chain doesn't match.
   */
  ZKSYNC_SEPOLIA_CHAIN_ID: string;

  /**
   * EIP-55 address of the sole `NullifierRegistry` this attester is
   * willing to sign for. Single-element allowlist; rotations are
   * deploy-time, not request-time.
   */
  NULLIFIER_REGISTRY_ADDRESS: string;

  // ── secrets (set via `wrangler secret put NAME`) ────────────────

  /**
   * 0x-prefixed 32-byte secp256k1 private key. Recover address must
   * match an address currently allow-listed in `SelfAttesterRegistry`
   * (otherwise on-chain `verifyAttesterSig` rejects every signature
   * this Worker produces).
   *
   * **Never log, persist, or echo this value.** The Worker reads it
   * once per request to derive a viem `Account`, then discards it.
   */
  ATTESTER_PRIVATE_KEY: string;
}
