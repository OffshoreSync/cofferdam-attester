// Copyright (c) 2026 Cofferdam Inc
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

  /**
   * 'development' | 'staging' | 'production'.
   *
   * Gate-keeps logging verbosity AND acts as the hard stop on
   * `BIND_GATE_MODE=attestation` — see the note on that var.
   */
  ENVIRONMENT: 'development' | 'staging' | 'production';

  /**
   * Base chain id, as a decimal string. Base Sepolia = '84532',
   * Base mainnet = '8453'. Hardcoded into the message-hash preimage;
   * the attester rejects sign requests whose target chain doesn't
   * match.
   *
   * Replaces the pre-Base `ZKSYNC_SEPOLIA_CHAIN_ID` var ('300'). If
   * mainnet ever lights up we deploy a separate attester Worker
   * rather than multiplexing chains through one signer.
   */
  BASE_CHAIN_ID: string;

  /**
   * Which evidence the attester requires before it will sign a bind.
   *
   *   'attestation' — Verify the Self enclave's GCP Confidential Space
   *                   attestation JWT and its image digest, then trust
   *                   the caller's reported pubSignals. TESTNET ONLY.
   *                   The attestation is a channel-binding credential
   *                   issued during the TEE handshake, BEFORE any proof
   *                   exists, so it cannot vouch for the nullifier that
   *                   accompanies it. A patched app can pair a genuine
   *                   attestation with a fabricated nullifier. See the
   *                   header comment in `selfAttestation.ts`.
   *
   *   'celo'        — Re-verify the Groth16 proof and the identity
   *                   commitment Merkle root against Self's registry
   *                   on Celo via `eth_call` before signing. A
   *                   compromised app cannot forge this because it
   *                   cannot write to Celo. Required for mainnet.
   *
   * `index.ts` refuses to boot a signing path with
   * `BIND_GATE_MODE=attestation` while `ENVIRONMENT=production`.
   */
  BIND_GATE_MODE: 'attestation' | 'celo';

  /**
   * Comma- and/or whitespace-separated allowlist of Self proving-enclave
   * image measurements, as sha256 hex (the `sha256:` prefix is optional
   * and stripped on parse).
   *
   * This is the value Self's own code calls "PCR0" — legacy AWS Nitro
   * naming retained after they migrated to GCP Confidential Space. It
   * is really `submods.container.image_digest` from the attestation JWT.
   * Self keeps their canonical allowlist on-chain in `PCR0Manager` at
   * 0xE36d4EE5Fd3916e703A46C21Bb3837dB7680C8B8 on Celo; we pin our own
   * copy so a Self-side allowlist addition cannot silently widen what
   * this attester accepts.
   *
   * Legitimately holds more than one entry during a Self enclave
   * rollout. Empty is only tolerated when ENVIRONMENT=development.
   */
  SELF_TEE_IMAGE_DIGESTS: string;

  /**
   * EIP-55 address of the sole `NullifierRegistry` this attester is
   * willing to sign for. Single-element allowlist; rotations are
   * deploy-time, not request-time.
   */
  NULLIFIER_REGISTRY_ADDRESS: string;

  /**
   * JWT `iss` claim baked into every `issueProverSession` response.
   * Hardcoded to "cofferdam-attester" in production; var-controlled
   * so staging can isolate.
   */
  JWT_ISSUER: string;

  /**
   * JWT `aud` claim baked into every `issueProverSession` response.
   * Hardcoded to "cofferdam-attester" in production.
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
   * `issueProverSession`. The verifying party holds the same
   * secret under the same name and uses it to VERIFY. Length:
   * ≥32 bytes of high-entropy randomness, base64url-encoded.
   *
   * Provision via:
   *
   *   openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
   *   wrangler secret put JWT_SHARED_SECRET
   *
   * For local dev, paste into `.dev.vars`:
   *   JWT_SHARED_SECRET=<the base64url value>
   *
   * Production-hardening (Session 5+): replace HMAC with an
   * asymmetric scheme (Ed25519 / ES256) so the verifier only ever
   * holds a public key. HS256 is acceptable for α/β because both
   * services are operated by Cofferdam Inc; the threat model
   * tightens once any consumer outside the trust boundary needs
   * to verify JWTs.
   */
  JWT_SHARED_SECRET: string;
}
