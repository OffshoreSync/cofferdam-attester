// Copyright (c) 2026 OffshoreSync LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Cofferdam Self attester Worker — entry point.
 *
 * Exposes a single RPC method, `signBind`, that returns an EIP-191
 * personal_sign over `NullifierRegistry.attesterMessageHash(...)`.
 * This Worker is the only place in the Cofferdam stack where the
 * SelfAttester private key is ever deserialised; every other surface
 * touches it via this binding.
 *
 * Defense layers (per IDENTITY_LAYER_DESIGN.md §4):
 *   1. `workers_dev: false` + zero routes → no public ingress.
 *   2. Service-binding only → only Workers in this Cloudflare account
 *      can reach this Worker.
 *   3. Pinned chain id + registry allowlist → a compromised consumer
 *      Worker cannot extract a signature usable on any other chain
 *      or against any other NullifierRegistry.
 *   4. Strict input validation → malformed `pubSignals` (wrong length,
 *      out-of-range field elements) reject before any signing happens.
 *   5. Audit log per request → every sign event hits Workers Logs
 *      with (account, registry, attestationId, scope, hash); replay
 *      auditor reconciles against on-chain `NullifierBound` events.
 */

import { WorkerEntrypoint } from 'cloudflare:workers';
import { getAddress, isAddress, isHex, type Hex } from 'viem';
import type { Env } from './env.js';
import type { AttesterRpc, SignBindRequest, SignBindResponse } from './rpc.js';
import { signBindAttestation } from './sign.js';

// ────────────────────────────────────────────────────────────────────
// Constants — `vc_and_disclose` public-signal indices.
// Mirrors contracts/v2/self/SelfPublicSignals.sol; the on-chain
// validation in `NullifierRegistry.verifyAndBind` will reject any
// proof whose pubSignals don't satisfy these, but we mirror them
// here so we can audit-log meaningful values per request.
// ────────────────────────────────────────────────────────────────────
const PUB_SIGNAL_INDEX = {
  NULLIFIER: 7,
  ATTESTATION_ID: 8,
  SCOPE: 19,
  USER_IDENTIFIER: 20,
} as const;

const PUB_SIGNALS_LENGTH = 21;

/** Max value of a uint256 — sanity-bound for incoming pubSignals. */
const UINT256_MAX = (1n << 256n) - 1n;

// ────────────────────────────────────────────────────────────────────
// Domain errors. Surfaced as throws over RPC; the runtime serialises
// them with the message intact so consumers can branch on `.message`.
// ────────────────────────────────────────────────────────────────────
class AttesterError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'AttesterError';
  }
}

function badRequest(code: string, message: string): never {
  throw new AttesterError(code, message);
}

// ────────────────────────────────────────────────────────────────────
// Validation helpers.
// ────────────────────────────────────────────────────────────────────

function parsePubSignals(raw: readonly string[]): bigint[] {
  if (!Array.isArray(raw) || raw.length !== PUB_SIGNALS_LENGTH) {
    badRequest(
      'BAD_PUBSIGNALS_LENGTH',
      `pubSignals must be an array of ${PUB_SIGNALS_LENGTH} decimal strings; got ${
        Array.isArray(raw) ? raw.length : typeof raw
      }`,
    );
  }
  const out: bigint[] = new Array(PUB_SIGNALS_LENGTH);
  for (let i = 0; i < PUB_SIGNALS_LENGTH; i++) {
    const s = raw[i];
    if (typeof s !== 'string' || !/^\d+$/.test(s)) {
      badRequest(
        'BAD_PUBSIGNAL_FORMAT',
        `pubSignals[${i}] must be a non-negative decimal string, got ${typeof s}`,
      );
    }
    let v: bigint;
    try {
      v = BigInt(s);
    } catch {
      badRequest('BAD_PUBSIGNAL_PARSE', `pubSignals[${i}] failed to parse as BigInt`);
    }
    if (v < 0n || v > UINT256_MAX) {
      badRequest('PUBSIGNAL_OUT_OF_RANGE', `pubSignals[${i}] out of uint256 range`);
    }
    out[i] = v;
  }
  return out;
}

/**
 * Best-effort hex private key sanity check. Doesn't validate the
 * curve order (viem does that on `privateKeyToAccount`).
 */
function assertPrivateKey(pk: string): asserts pk is Hex {
  if (!isHex(pk) || pk.length !== 66 /* 0x + 64 hex chars */) {
    throw new AttesterError(
      'BAD_ATTESTER_KEY',
      'ATTESTER_PRIVATE_KEY secret is missing or malformed (expected 0x + 64 hex chars)',
    );
  }
}

// ────────────────────────────────────────────────────────────────────
// Worker.
// ────────────────────────────────────────────────────────────────────

export default class CofferdamAttester
  extends WorkerEntrypoint<Env>
  implements AttesterRpc
{
  /**
   * Sign a bind attestation.
   *
   * Validates inputs, recomputes `attesterMessageHash` exactly as the
   * on-chain `NullifierRegistry`, signs with EIP-191 personal_sign,
   * and emits an audit log line.
   */
  async signBind(req: SignBindRequest): Promise<SignBindResponse> {
    // ── Pull pinned values from env ─────────────────────────────
    const chainIdStr = this.env.ZKSYNC_SEPOLIA_CHAIN_ID;
    if (!/^\d+$/.test(chainIdStr)) {
      throw new AttesterError(
        'BAD_CHAIN_ID_VAR',
        `ZKSYNC_SEPOLIA_CHAIN_ID var is malformed: ${chainIdStr}`,
      );
    }
    const chainId = BigInt(chainIdStr);

    const allowedRegistryRaw = this.env.NULLIFIER_REGISTRY_ADDRESS;
    if (!isAddress(allowedRegistryRaw)) {
      throw new AttesterError(
        'BAD_REGISTRY_VAR',
        `NULLIFIER_REGISTRY_ADDRESS var is malformed: ${allowedRegistryRaw}`,
      );
    }
    const allowedRegistry = getAddress(allowedRegistryRaw);

    // ── Validate request shape ──────────────────────────────────
    if (!req || typeof req !== 'object') {
      badRequest('BAD_REQUEST', 'request body is missing or not an object');
    }
    if (typeof req.registry !== 'string' || !isAddress(req.registry)) {
      badRequest('BAD_REGISTRY', 'request.registry is not a valid address');
    }
    if (typeof req.account !== 'string' || !isAddress(req.account)) {
      badRequest('BAD_ACCOUNT', 'request.account is not a valid address');
    }
    const requestedRegistry = getAddress(req.registry);
    const requestedAccount = getAddress(req.account);

    // ── Pinned-registry allowlist (defense-in-depth) ────────────
    if (requestedRegistry !== allowedRegistry) {
      badRequest(
        'REGISTRY_NOT_ALLOWED',
        `attester refuses to sign for registry ${requestedRegistry}; ` +
          `pinned registry is ${allowedRegistry}`,
      );
    }

    const pubSignals = parsePubSignals(req.pubSignals);

    // ── Cross-field consistency (cheap pre-flight) ──────────────
    // The on-chain registry already enforces these; doing it here
    // turns a confusing `verifyAttesterSig` failure on-chain into
    // a clear off-chain error before we waste gas.
    const userIdentifier = pubSignals[PUB_SIGNAL_INDEX.USER_IDENTIFIER]!;
    const accountAsUint = BigInt(requestedAccount);
    if (userIdentifier !== accountAsUint) {
      badRequest(
        'USER_IDENTIFIER_MISMATCH',
        `pubSignals[USER_IDENTIFIER] (${userIdentifier}) does not equal account (${accountAsUint})`,
      );
    }

    // ── Sign ────────────────────────────────────────────────────
    assertPrivateKey(this.env.ATTESTER_PRIVATE_KEY);
    const signed = await signBindAttestation(this.env.ATTESTER_PRIVATE_KEY, {
      chainId,
      registry: requestedRegistry,
      account: requestedAccount,
      pubSignals,
    });

    // ── Audit log ───────────────────────────────────────────────
    // Privacy-safe: account + registry + chainId + attestationId +
    // scope + nullifier (the nullifier is already public on bind,
    // so logging it here is equivalent in linkability). We do NOT
    // log the full pubSignals (could include packed birth-year
    // disclosure data depending on Self circuit version).
    console.log(
      JSON.stringify({
        kind: 'attester.signBind',
        environment: this.env.ENVIRONMENT,
        chainId: chainIdStr,
        registry: requestedRegistry,
        account: requestedAccount,
        attestationId: pubSignals[PUB_SIGNAL_INDEX.ATTESTATION_ID]!.toString(),
        scope: pubSignals[PUB_SIGNAL_INDEX.SCOPE]!.toString(),
        nullifier: pubSignals[PUB_SIGNAL_INDEX.NULLIFIER]!.toString(),
        attesterAddress: signed.attesterAddress,
        messageHash: signed.messageHash,
      }),
    );

    return {
      attesterAddress: signed.attesterAddress,
      messageHash: signed.messageHash,
      signature: signed.signature,
      chainId: chainIdStr,
      registry: requestedRegistry,
      account: requestedAccount,
    };
  }

  /**
   * Non-RPC fetch handler. The Worker is service-binding only, but
   * Cloudflare requires `default export.fetch` to exist; returning
   * 405 makes the boundary explicit if anyone ever flips
   * `workers_dev: true` by accident.
   */
  override async fetch(): Promise<Response> {
    return new Response(
      'cofferdam-attester is service-binding-only; use the ATTESTER RPC',
      { status: 405 },
    );
  }
}
