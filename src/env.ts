// Copyright (c) 2026 OffshoreSync LLC
// SPDX-License-Identifier: Apache-2.0

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

  /**
   * JWT `iss` claim baked into every `issueProverSession` response.
   * Must equal what `cofferdam-prover` expects (its own `JWT_ISSUER`
   * var). Hardcoded to "cofferdam-attester" in production; var-controlled
   * so staging can isolate.
   */
  JWT_ISSUER: string;

  /**
   * JWT `aud` claim baked into every `issueProverSession` response.
   * Must equal what `cofferdam-prover` expects (its own `JWT_AUDIENCE`
   * var). Hardcoded to "cofferdam-prover" in production.
   */
  JWT_AUDIENCE: string;

  /**
   * Seconds of TTL on JWTs issued via `issueProverSession`. The
   * IDENTITY_LAYER_DESIGN.md §5 hardening list calls for 60-second
   * sessions; this var lets staging shorten further (e.g. 10s) for
   * replay-attack rehearsals without a Worker rebuild.
   */
  PROVER_SESSION_TTL_SECONDS: string;

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

  /**
   * HMAC-SHA256 shared secret used to SIGN JWTs returned by
   * `issueProverSession`. The cofferdam-prover Worker holds the same
   * secret under the same name and uses it to VERIFY. Length:
   * ≥32 bytes of high-entropy randomness, base64url-encoded.
   *
   * MUST BE IDENTICAL to `JWT_SHARED_SECRET` in cofferdam-prover.
   * Provision via:
   *
   *   openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
   *   wrangler secret put JWT_SHARED_SECRET   # in BOTH workers
   *
   * For local dev, paste into `.dev.vars` in both repos:
   *   JWT_SHARED_SECRET=<the base64url value>
   *
   * Production-hardening (Session 5+): replace HMAC with an
   * asymmetric scheme (Ed25519 / ES256) so the prover only ever
   * holds a public key. HS256 is acceptable for α/β because both
   * Workers are operated by OffshoreSync LLC; the threat model
   * tightens once any consumer outside the trust boundary needs
   * to verify JWTs.
   */
  JWT_SHARED_SECRET: string;
}
