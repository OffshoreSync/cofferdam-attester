// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { Address } from 'viem';

import {
  CeloGateError,
  E_PASSPORT_ATTESTATION_KEY,
  PASSPORT_DISCLOSE_INDEX,
  assertProofDateFresh,
  parseProofDate,
  verifyProofOnCelo,
  type CeloGateConfig,
  type CeloReads,
} from '../src/celoGate.js';

const HUB: Address = '0xe57F4773bd9c9d8b6Cd70431117d353298B9f5BF';
const REGISTRY: Address = '0x37F5CB8cB1f6B00aa768D8aA99F1A9289802A968';
const OTHER_REGISTRY: Address = '0x0000000000000000000000000000000000000Bad';

// Values read from Celo mainnet on 2026-10-10 (tree size 5200).
const ROOT = 1028250853844545477525675497463046671568825934242895532070630707193360198082n;
const OFAC = {
  passportNo: 3401417420280718516738171609390626784619095029610962469425010828214197157747n,
  nameDob: 6227060330278404862591977884131255780942563186873190571034622155790997155169n,
  nameYob: 21056015788554834534165942295360655227086483475348760845000192264553821912934n,
};

const CONFIG: CeloGateConfig = { chainId: 42220n, hub: HUB, passportRegistry: REGISTRY };

/** A fixed "now" so the date window is deterministic: 2026-10-10T12:00Z. */
const NOW = new Date(Date.UTC(2026, 9, 10, 12, 0, 0));

function dateDigits(yy: number, mm: number, dd: number): bigint[] {
  return `${String(yy).padStart(2, '0')}${String(mm).padStart(2, '0')}${String(dd).padStart(2, '0')}`
    .split('')
    .map((d) => BigInt(d));
}

function pubSignalsFor(overrides: Partial<Record<number, bigint>> = {}, date = dateDigits(26, 10, 10)): bigint[] {
  const s = new Array<bigint>(21).fill(0n);
  s[PASSPORT_DISCLOSE_INDEX.NULLIFIER] = 777n;
  s[PASSPORT_DISCLOSE_INDEX.ATTESTATION_ID] = 1n;
  s[PASSPORT_DISCLOSE_INDEX.MERKLE_ROOT] = ROOT;
  date.forEach((d, i) => {
    s[PASSPORT_DISCLOSE_INDEX.CURRENT_DATE_START + i] = d;
  });
  s[PASSPORT_DISCLOSE_INDEX.PASSPORT_NO_SMT_ROOT] = OFAC.passportNo;
  s[PASSPORT_DISCLOSE_INDEX.NAMEDOB_SMT_ROOT] = OFAC.nameDob;
  s[PASSPORT_DISCLOSE_INDEX.NAMEYOB_SMT_ROOT] = OFAC.nameYob;
  s[PASSPORT_DISCLOSE_INDEX.SCOPE] = 42n;
  s[PASSPORT_DISCLOSE_INDEX.USER_IDENTIFIER] = 99n;
  for (const [k, v] of Object.entries(overrides)) s[Number(k)] = v!;
  return s;
}

/** Fixture reads modelled on the live registry: one known root, current OFAC roots. */
function fixtureReads(overrides: Partial<CeloReads> = {}): CeloReads & { calls: string[] } {
  const calls: string[] = [];
  const base: CeloReads = {
    async chainId() {
      calls.push('chainId');
      return 42220n;
    },
    async hubRegistry(hub, key) {
      calls.push(`hubRegistry:${hub}:${key}`);
      return REGISTRY;
    },
    async checkIdentityCommitmentRoot(registry, root) {
      calls.push(`checkRoot:${registry}:${root}`);
      return root === ROOT;
    },
    async checkOfacRoots(registry, a, b, c) {
      calls.push(`checkOfac:${registry}`);
      return a === OFAC.passportNo && b === OFAC.nameDob && c === OFAC.nameYob;
    },
  };
  return Object.assign({ calls }, base, overrides);
}

async function expectGateError(p: Promise<unknown>, code: CeloGateError['code'], retryable = false) {
  const err = await p.then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(CeloGateError);
  expect((err as CeloGateError).code).toBe(code);
  expect((err as CeloGateError).retryable).toBe(retryable);
}

describe('parseProofDate', () => {
  it('decodes six digit signals as a UTC calendar date', () => {
    const d = parseProofDate(pubSignalsFor({}, dateDigits(26, 10, 10)));
    expect(d).toMatchObject({ year: 2026, month: 10, day: 10, iso: '2026-10-10' });
    expect(d.utcMs).toBe(Date.UTC(2026, 9, 10));
  });

  it('rejects a signal that is not a single digit', () => {
    const s = pubSignalsFor();
    s[PASSPORT_DISCLOSE_INDEX.CURRENT_DATE_START] = 10n;
    expect(() => parseProofDate(s)).toThrowError(/single decimal digit/);
    s[PASSPORT_DISCLOSE_INDEX.CURRENT_DATE_START] = 48n; // ASCII '0', not a digit value
    expect(() => parseProofDate(s)).toThrowError(/single decimal digit/);
  });

  it('rejects impossible calendar dates', () => {
    expect(() => parseProofDate(pubSignalsFor({}, dateDigits(26, 2, 30)))).toThrowError(/calendar/);
    expect(() => parseProofDate(pubSignalsFor({}, dateDigits(26, 13, 1)))).toThrowError(/calendar/);
    expect(() => parseProofDate(pubSignalsFor({}, dateDigits(26, 0, 1)))).toThrowError(/calendar/);
    expect(() => parseProofDate(pubSignalsFor({}, dateDigits(26, 1, 0)))).toThrowError(/calendar/);
  });

  it('accepts leap days', () => {
    expect(parseProofDate(pubSignalsFor({}, dateDigits(28, 2, 29))).iso).toBe('2028-02-29');
  });
});

describe('assertProofDateFresh', () => {
  it('accepts yesterday, today and tomorrow (UTC) and rejects beyond', () => {
    const ok = (yy: number, mm: number, dd: number) =>
      assertProofDateFresh(parseProofDate(pubSignalsFor({}, dateDigits(yy, mm, dd))), NOW);
    expect(() => ok(26, 10, 9)).not.toThrow();
    expect(() => ok(26, 10, 10)).not.toThrow();
    expect(() => ok(26, 10, 11)).not.toThrow();
    expect(() => ok(26, 10, 8)).toThrowError(/outside/);
    expect(() => ok(26, 10, 12)).toThrowError(/outside/);
  });

  it('uses UTC midnight, not local time', () => {
    const lateEvening = new Date(Date.UTC(2026, 9, 10, 23, 59, 59));
    expect(() =>
      assertProofDateFresh(parseProofDate(pubSignalsFor({}, dateDigits(26, 10, 9))), lateEvening),
    ).not.toThrow();
    expect(() =>
      assertProofDateFresh(parseProofDate(pubSignalsFor({}, dateDigits(26, 10, 8))), lateEvening),
    ).toThrowError(/outside/);
  });
});

describe('verifyProofOnCelo', () => {
  it('passes a proof whose root, OFAC roots and date all check out', async () => {
    const reads = fixtureReads();
    const result = await verifyProofOnCelo(reads, CONFIG, pubSignalsFor(), NOW);
    expect(result).toEqual({
      chainId: 42220n,
      registry: REGISTRY,
      merkleRoot: ROOT,
      ofacRoots: OFAC,
      proofDate: '2026-10-10',
    });
    expect(reads.calls).toContain('chainId');
    expect(reads.calls).toContain(`hubRegistry:${HUB}:${E_PASSPORT_ATTESTATION_KEY}`);
    expect(reads.calls).toContain(`checkRoot:${REGISTRY}:${ROOT}`);
    expect(reads.calls).toContain(`checkOfac:${REGISTRY}`);
  });

  it('refuses before any network call when the local checks fail', async () => {
    const reads = fixtureReads();
    await expectGateError(
      verifyProofOnCelo(reads, CONFIG, pubSignalsFor({ [PASSPORT_DISCLOSE_INDEX.ATTESTATION_ID]: 2n }), NOW),
      'WRONG_ATTESTATION_ID',
    );
    await expectGateError(
      verifyProofOnCelo(reads, CONFIG, pubSignalsFor({}, dateDigits(26, 9, 1)), NOW),
      'PROOF_DATE_OUT_OF_WINDOW',
    );
    await expectGateError(verifyProofOnCelo(reads, CONFIG, pubSignalsFor().slice(0, 20), NOW), 'BAD_PUBSIGNALS_LENGTH');
    expect(reads.calls).toEqual([]);
  });

  it('refuses a root Self never published', async () => {
    await expectGateError(
      verifyProofOnCelo(fixtureReads(), CONFIG, pubSignalsFor({ [PASSPORT_DISCLOSE_INDEX.MERKLE_ROOT]: 12345n }), NOW),
      'CELO_ROOT_UNKNOWN',
    );
  });

  it('refuses stale OFAC roots', async () => {
    await expectGateError(
      verifyProofOnCelo(fixtureReads(), CONFIG, pubSignalsFor({ [PASSPORT_DISCLOSE_INDEX.NAMEYOB_SMT_ROOT]: 1n }), NOW),
      'CELO_OFAC_ROOTS_STALE',
    );
  });

  it('refuses when the RPC answers for another chain', async () => {
    await expectGateError(
      verifyProofOnCelo(fixtureReads({ chainId: async () => 11142220n }), CONFIG, pubSignalsFor(), NOW),
      'CELO_CHAIN_MISMATCH',
    );
  });

  it('refuses when the hub no longer routes E_PASSPORT to the pinned registry', async () => {
    await expectGateError(
      verifyProofOnCelo(fixtureReads({ hubRegistry: async () => OTHER_REGISTRY }), CONFIG, pubSignalsFor(), NOW),
      'CELO_REGISTRY_MISMATCH',
    );
  });

  it('marks RPC failures retryable and never treats them as a bad proof', async () => {
    await expectGateError(
      verifyProofOnCelo(
        fixtureReads({
          checkIdentityCommitmentRoot: async () => {
            throw new Error('HTTP request failed');
          },
        }),
        CONFIG,
        pubSignalsFor(),
        NOW,
      ),
      'CELO_RPC_UNAVAILABLE',
      true,
    );
  });
});
