// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * Celo bind gate (decision 0004).
 *
 * Self.xyz proves a passport inside its own enclave and anchors the result
 * on Celo: the identity-commitment Merkle tree, the OFAC sparse-Merkle roots
 * and the hub that maps each attestation type to its registry all live
 * there. Our `NullifierRegistry` on Base verifies the Groth16 proof itself,
 * but a Groth16 proof only shows "this commitment is a leaf of the tree with
 * root R" — it cannot show that R is one of Self's roots. A forged tree
 * yields a perfectly valid proof over an invented commitment, so without
 * this gate anyone could mint nullifiers. The attester therefore asks Celo
 * (read-only `eth_call`) the same questions
 * `IdentityVerificationHubImplV2._basicVerification` asks when a proof is
 * consumed natively, before it signs anything:
 *
 *   1. `hub.registry(E_PASSPORT)` is still the registry we pinned;
 *   2. `registry.checkIdentityCommitmentRoot(pubSignals[MERKLE_ROOT])` —
 *      roots never expire, so this is membership over every root Self has
 *      ever published;
 *   3. `registry.checkOfacRoots(passportNo, nameDob, nameYob)` — the proof
 *      was computed against the current or immediately previous sanctions
 *      snapshot;
 *   4. the proof's `currentDate` signals fall within a day of now.
 *
 * The Groth16 proof is verified on Base by `Verifier_vc_and_disclose`; the
 * attester signs over the public signals only, so a tampered proof reverts
 * on-chain instead of being accepted here.
 *
 * Network access is injected through `CeloReads`: the Worker backs it with
 * viem (`createCeloReads`), the unit tests back it with fixtures.
 */

import { createPublicClient, getAddress, http, type Address, type Hex } from 'viem';

/** Self `AttestationId.E_PASSPORT` as the circuit emits it. */
export const E_PASSPORT_ATTESTATION_ID = 1n;

/** `bytes32(uint256(1))` — the hub keys its registries by attestation id. */
export const E_PASSPORT_ATTESTATION_KEY: Hex = `0x${'0'.repeat(63)}1`;

/**
 * `vc_and_disclose` public-signal indices for E_PASSPORT. Mirrors Self's
 * `CircuitConstantsV2.getDiscloseIndices(E_PASSPORT)` and our
 * `contracts/self/SelfPublicSignals.sol` on Base.
 */
export const PASSPORT_DISCLOSE_INDEX = {
  NULLIFIER: 7,
  ATTESTATION_ID: 8,
  MERKLE_ROOT: 9,
  /** Six consecutive single-digit signals: YYMMDD. */
  CURRENT_DATE_START: 10,
  PASSPORT_NO_SMT_ROOT: 16,
  NAMEDOB_SMT_ROOT: 17,
  NAMEYOB_SMT_ROOT: 18,
  SCOPE: 19,
  USER_IDENTIFIER: 20,
} as const;

export const PUB_SIGNALS_LENGTH = 21;

/**
 * Proof dates this far either side of today's UTC midnight are accepted.
 * Self's hub accepts only the current UTC day; its backend verifier accepts
 * ±1 day. We take the lenient window: Base's registry does not check dates
 * at all, so this is a freshness hygiene check, not a consensus rule.
 */
export const PROOF_DATE_WINDOW_MS = 24 * 60 * 60 * 1000;

export type CeloGateErrorCode =
  | 'BAD_PUBSIGNALS_LENGTH'
  | 'WRONG_ATTESTATION_ID'
  | 'PROOF_DATE_MALFORMED'
  | 'PROOF_DATE_OUT_OF_WINDOW'
  | 'CELO_RPC_UNAVAILABLE'
  | 'CELO_CHAIN_MISMATCH'
  | 'CELO_REGISTRY_MISMATCH'
  | 'CELO_ROOT_UNKNOWN'
  | 'CELO_OFAC_ROOTS_STALE';

export class CeloGateError extends Error {
  constructor(
    public readonly code: CeloGateErrorCode,
    message: string,
    /** True when the RPC failed rather than the proof — callers may retry. */
    public readonly retryable = false,
  ) {
    super(message);
    this.name = 'CeloGateError';
  }
}

/** The four reads the gate needs. Keep this surface minimal: it is the attester's only egress. */
export interface CeloReads {
  chainId(): Promise<bigint>;
  hubRegistry(hub: Address, attestationKey: Hex): Promise<Address>;
  checkIdentityCommitmentRoot(registry: Address, root: bigint): Promise<boolean>;
  checkOfacRoots(
    registry: Address,
    passportNoRoot: bigint,
    nameDobRoot: bigint,
    nameYobRoot: bigint,
  ): Promise<boolean>;
}

export interface CeloGateConfig {
  /** Celo chain id the RPC must report (mainnet 42220). */
  readonly chainId: bigint;
  /** `IdentityVerificationHubImplV2` proxy. */
  readonly hub: Address;
  /** `IdentityRegistryImplV1` proxy for E_PASSPORT, as the hub must report it. */
  readonly passportRegistry: Address;
}

export interface CeloGateResult {
  readonly chainId: bigint;
  readonly registry: Address;
  readonly merkleRoot: bigint;
  readonly ofacRoots: {
    readonly passportNo: bigint;
    readonly nameDob: bigint;
    readonly nameYob: bigint;
  };
  /** ISO `YYYY-MM-DD` decoded from the proof's `currentDate` signals. */
  readonly proofDate: string;
}

export interface ProofDate {
  readonly year: number;
  readonly month: number;
  readonly day: number;
  /** UTC midnight of the proof date, in ms since the epoch. */
  readonly utcMs: number;
  readonly iso: string;
}

/**
 * Decode `pubSignals[10..15]` (six single-digit signals, YYMMDD) into a UTC
 * calendar date. Mirrors `Formatter.proofDateToUnixTimestamp` on Celo,
 * including its digit-range and calendar checks.
 */
export function parseProofDate(pubSignals: readonly bigint[]): ProofDate {
  const start = PASSPORT_DISCLOSE_INDEX.CURRENT_DATE_START;
  const digits: number[] = [];
  for (let i = 0; i < 6; i++) {
    const v = pubSignals[start + i];
    if (v === undefined || v < 0n || v > 9n) {
      throw new CeloGateError(
        'PROOF_DATE_MALFORMED',
        `pubSignals[${start + i}] must be a single decimal digit, got ${
          v === undefined ? 'nothing' : v.toString()
        }`,
      );
    }
    digits.push(Number(v));
  }
  const year = 2000 + digits[0]! * 10 + digits[1]!;
  const month = digits[2]! * 10 + digits[3]!;
  const day = digits[4]! * 10 + digits[5]!;
  const utcMs = Date.UTC(year, month - 1, day);
  const roundTrip = new Date(utcMs);
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    roundTrip.getUTCFullYear() !== year ||
    roundTrip.getUTCMonth() !== month - 1 ||
    roundTrip.getUTCDate() !== day
  ) {
    throw new CeloGateError(
      'PROOF_DATE_MALFORMED',
      `proof date ${digits.join('')} (YYMMDD) is not a calendar date`,
    );
  }
  const iso = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
  return { year, month, day, utcMs, iso };
}

/** Reject proofs whose date is more than `PROOF_DATE_WINDOW_MS` from today's UTC midnight. */
export function assertProofDateFresh(proof: ProofDate, now: Date): void {
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  if (Math.abs(proof.utcMs - today) > PROOF_DATE_WINDOW_MS) {
    throw new CeloGateError(
      'PROOF_DATE_OUT_OF_WINDOW',
      `proof dated ${proof.iso} is outside the ±1 day window around ${
        new Date(today).toISOString().slice(0, 10)
      }`,
    );
  }
}

/**
 * Run the gate. Local checks first (attestation id, date), then the four
 * Celo reads in parallel. Throws `CeloGateError`; never signs anything.
 */
export async function verifyProofOnCelo(
  reads: CeloReads,
  config: CeloGateConfig,
  pubSignals: readonly bigint[],
  now: Date = new Date(),
): Promise<CeloGateResult> {
  if (pubSignals.length !== PUB_SIGNALS_LENGTH) {
    throw new CeloGateError(
      'BAD_PUBSIGNALS_LENGTH',
      `expected ${PUB_SIGNALS_LENGTH} public signals, got ${pubSignals.length}`,
    );
  }

  const attestationId = pubSignals[PASSPORT_DISCLOSE_INDEX.ATTESTATION_ID]!;
  if (attestationId !== E_PASSPORT_ATTESTATION_ID) {
    throw new CeloGateError(
      'WRONG_ATTESTATION_ID',
      `only E_PASSPORT (${E_PASSPORT_ATTESTATION_ID}) proofs bind; got ${attestationId.toString()}`,
    );
  }

  const proofDate = parseProofDate(pubSignals);
  assertProofDateFresh(proofDate, now);

  const merkleRoot = pubSignals[PASSPORT_DISCLOSE_INDEX.MERKLE_ROOT]!;
  const ofacRoots = {
    passportNo: pubSignals[PASSPORT_DISCLOSE_INDEX.PASSPORT_NO_SMT_ROOT]!,
    nameDob: pubSignals[PASSPORT_DISCLOSE_INDEX.NAMEDOB_SMT_ROOT]!,
    nameYob: pubSignals[PASSPORT_DISCLOSE_INDEX.NAMEYOB_SMT_ROOT]!,
  };

  let chainId: bigint;
  let hubRegistry: Address;
  let rootKnown: boolean;
  let ofacFresh: boolean;
  try {
    [chainId, hubRegistry, rootKnown, ofacFresh] = await Promise.all([
      reads.chainId(),
      reads.hubRegistry(config.hub, E_PASSPORT_ATTESTATION_KEY),
      reads.checkIdentityCommitmentRoot(config.passportRegistry, merkleRoot),
      reads.checkOfacRoots(
        config.passportRegistry,
        ofacRoots.passportNo,
        ofacRoots.nameDob,
        ofacRoots.nameYob,
      ),
    ]);
  } catch (err) {
    throw new CeloGateError(
      'CELO_RPC_UNAVAILABLE',
      `Celo read failed: ${err instanceof Error ? err.message : String(err)}`,
      true,
    );
  }

  if (chainId !== config.chainId) {
    throw new CeloGateError(
      'CELO_CHAIN_MISMATCH',
      `Celo RPC reports chain ${chainId.toString()}, pinned ${config.chainId.toString()}`,
    );
  }
  if (getAddress(hubRegistry) !== getAddress(config.passportRegistry)) {
    throw new CeloGateError(
      'CELO_REGISTRY_MISMATCH',
      `hub routes E_PASSPORT to ${getAddress(hubRegistry)}, pinned ${getAddress(
        config.passportRegistry,
      )}; Self migrated its registry — re-pin after review`,
    );
  }
  if (!rootKnown) {
    throw new CeloGateError(
      'CELO_ROOT_UNKNOWN',
      `identity-commitment root ${merkleRoot.toString()} was never published by Self's passport registry`,
    );
  }
  if (!ofacFresh) {
    throw new CeloGateError(
      'CELO_OFAC_ROOTS_STALE',
      'proof was computed against OFAC roots that are neither current nor previous on Celo; re-prove',
    );
  }

  return {
    chainId,
    registry: getAddress(hubRegistry),
    merkleRoot,
    ofacRoots,
    proofDate: proofDate.iso,
  };
}

// ────────────────────────────────────────────────────────────────────
// viem-backed reads.
// ────────────────────────────────────────────────────────────────────

const HUB_ABI = [
  {
    type: 'function',
    name: 'registry',
    stateMutability: 'view',
    inputs: [{ name: 'attestationId', type: 'bytes32' }],
    outputs: [{ type: 'address' }],
  },
] as const;

const REGISTRY_ABI = [
  {
    type: 'function',
    name: 'checkIdentityCommitmentRoot',
    stateMutability: 'view',
    inputs: [{ name: 'root', type: 'uint256' }],
    outputs: [{ type: 'bool' }],
  },
  {
    type: 'function',
    name: 'checkOfacRoots',
    stateMutability: 'view',
    inputs: [
      { name: 'passportNoRoot', type: 'uint256' },
      { name: 'nameAndDobRoot', type: 'uint256' },
      { name: 'nameAndYobRoot', type: 'uint256' },
    ],
    outputs: [{ type: 'bool' }],
  },
] as const;

/**
 * Build `CeloReads` over a JSON-RPC endpoint. Chain-agnostic on purpose:
 * `verifyProofOnCelo` checks `eth_chainId` against the pinned value, so a
 * mis-pointed URL fails closed instead of answering for the wrong chain.
 */
export function createCeloReads(rpcUrl: string): CeloReads {
  const client = createPublicClient({
    transport: http(rpcUrl, { timeout: 10_000, retryCount: 2 }),
  });
  return {
    chainId: async () => BigInt(await client.getChainId()),
    hubRegistry: (hub, attestationKey) =>
      client.readContract({
        address: hub,
        abi: HUB_ABI,
        functionName: 'registry',
        args: [attestationKey],
      }),
    checkIdentityCommitmentRoot: (registry, root) =>
      client.readContract({
        address: registry,
        abi: REGISTRY_ABI,
        functionName: 'checkIdentityCommitmentRoot',
        args: [root],
      }),
    checkOfacRoots: (registry, passportNoRoot, nameDobRoot, nameYobRoot) =>
      client.readContract({
        address: registry,
        abi: REGISTRY_ABI,
        functionName: 'checkOfacRoots',
        args: [passportNoRoot, nameDobRoot, nameYobRoot],
      }),
  };
}
