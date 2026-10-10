// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * Live check of the viem-backed Celo reads against forno.celo.org.
 * Skipped unless `CELO_LIVE=1` so CI stays offline.
 */

import { describe, expect, it } from 'vitest';
import { createPublicClient, http, parseAbi, type Address } from 'viem';

import {
  CeloGateError,
  PASSPORT_DISCLOSE_INDEX,
  createCeloReads,
  verifyProofOnCelo,
  type CeloGateConfig,
} from '../src/celoGate.js';

const RPC = process.env.CELO_RPC_URL ?? 'https://forno.celo.org';
const CONFIG: CeloGateConfig = {
  chainId: 42220n,
  hub: '0xe57F4773bd9c9d8b6Cd70431117d353298B9f5BF',
  passportRegistry: '0x37F5CB8cB1f6B00aa768D8aA99F1A9289802A968',
};

const REGISTRY_READS = parseAbi([
  'function getIdentityCommitmentMerkleRoot() view returns (uint256)',
  'function getPassportNoOfacRoot() view returns (uint256)',
  'function getNameAndDobOfacRoot() view returns (uint256)',
  'function getNameAndYobOfacRoot() view returns (uint256)',
]);

function todayDigits(): bigint[] {
  const now = new Date();
  const yy = String(now.getUTCFullYear() % 100).padStart(2, '0');
  const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(now.getUTCDate()).padStart(2, '0');
  return `${yy}${mm}${dd}`.split('').map((d) => BigInt(d));
}

describe.skipIf(!process.env.CELO_LIVE)('Celo gate against forno (CELO_LIVE=1)', () => {
  it('accepts signals carrying the current root and OFAC roots, refuses a bogus root', async () => {
    const client = createPublicClient({ transport: http(RPC) });
    const read = <T>(functionName: 'getIdentityCommitmentMerkleRoot' | 'getPassportNoOfacRoot' | 'getNameAndDobOfacRoot' | 'getNameAndYobOfacRoot') =>
      client.readContract({ address: CONFIG.passportRegistry as Address, abi: REGISTRY_READS, functionName }) as Promise<T>;
    const [root, passportNo, nameDob, nameYob] = await Promise.all([
      read<bigint>('getIdentityCommitmentMerkleRoot'),
      read<bigint>('getPassportNoOfacRoot'),
      read<bigint>('getNameAndDobOfacRoot'),
      read<bigint>('getNameAndYobOfacRoot'),
    ]);

    const s = new Array<bigint>(21).fill(0n);
    s[PASSPORT_DISCLOSE_INDEX.ATTESTATION_ID] = 1n;
    s[PASSPORT_DISCLOSE_INDEX.MERKLE_ROOT] = root;
    todayDigits().forEach((d, i) => {
      s[PASSPORT_DISCLOSE_INDEX.CURRENT_DATE_START + i] = d;
    });
    s[PASSPORT_DISCLOSE_INDEX.PASSPORT_NO_SMT_ROOT] = passportNo;
    s[PASSPORT_DISCLOSE_INDEX.NAMEDOB_SMT_ROOT] = nameDob;
    s[PASSPORT_DISCLOSE_INDEX.NAMEYOB_SMT_ROOT] = nameYob;

    const reads = createCeloReads(RPC);
    const result = await verifyProofOnCelo(reads, CONFIG, s);
    expect(result.chainId).toBe(42220n);
    expect(result.registry).toBe(CONFIG.passportRegistry);
    expect(result.merkleRoot).toBe(root);

    const bogus = [...s];
    bogus[PASSPORT_DISCLOSE_INDEX.MERKLE_ROOT] = 12345n;
    const err = await verifyProofOnCelo(reads, CONFIG, bogus).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(CeloGateError);
    expect((err as CeloGateError).code).toBe('CELO_ROOT_UNKNOWN');
  }, 60_000);
});
