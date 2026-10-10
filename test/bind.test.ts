// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { concat, encodePacked, pad, type Hex } from 'viem';

import { AttesterError, parsePubSignals, prepareBindRequest, type BindPins } from '../src/bind.js';
import { PASSPORT_DISCLOSE_INDEX } from '../src/celoGate.js';
import { calculateUserIdentifierHash } from '../src/sign.js';
import type { SignBindRequest } from '../src/rpc.js';

const REGISTRY: Hex = '0x2843F55C9E1491a6d47F65f041E68F96E3aeB3d4';
const ACCOUNT: Hex = '0xfa4D920d5592289A1A0F73CA49D626EF8FE4D695';
const OTHER_ACCOUNT: Hex = '0x000000000000000000000000000000000000dEaD';
const PINS: BindPins = { chainIdStr: '84532', allowedRegistryRaw: REGISTRY };

/** `abi.encodePacked(bytes32(destChainId), bytes32(userId), userDefinedData)` as Self builds it. */
function userContextData(account: Hex, destChainId = 42220n, userDefinedData: Hex = '0x'): Hex {
  return concat([encodePacked(['uint256'], [destChainId]), pad(account, { size: 32 }), userDefinedData]);
}

function validRequest(overrides: Partial<SignBindRequest> = {}): SignBindRequest {
  const ctx = userContextData(ACCOUNT);
  const pubSignals = new Array<bigint>(21).fill(0n);
  pubSignals[PASSPORT_DISCLOSE_INDEX.NULLIFIER] = 555n;
  pubSignals[PASSPORT_DISCLOSE_INDEX.ATTESTATION_ID] = 1n;
  pubSignals[PASSPORT_DISCLOSE_INDEX.USER_IDENTIFIER] = calculateUserIdentifierHash(ctx);
  return {
    registry: REGISTRY,
    account: ACCOUNT,
    pubSignals: pubSignals.map((x) => x.toString()),
    userContextData: ctx,
    ...overrides,
  };
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(AttesterError);
    return (err as AttesterError).code;
  }
  throw new Error('expected a throw');
}

describe('parsePubSignals', () => {
  it('parses 21 decimal strings', () => {
    const parsed = parsePubSignals(new Array(21).fill('7'));
    expect(parsed).toHaveLength(21);
    expect(parsed.every((v) => v === 7n)).toBe(true);
  });

  it('rejects wrong length, non-decimal and out-of-range values', () => {
    expect(codeOf(() => parsePubSignals(new Array(20).fill('1')))).toBe('BAD_PUBSIGNALS_LENGTH');
    expect(codeOf(() => parsePubSignals([...new Array(20).fill('1'), '0x1']))).toBe('BAD_PUBSIGNAL_FORMAT');
    expect(codeOf(() => parsePubSignals([...new Array(20).fill('1'), '-1']))).toBe('BAD_PUBSIGNAL_FORMAT');
    expect(codeOf(() => parsePubSignals([...new Array(20).fill('1'), (1n << 256n).toString()]))).toBe(
      'PUBSIGNAL_OUT_OF_RANGE',
    );
  });
});

describe('prepareBindRequest', () => {
  it('accepts a well-formed request and decodes the Self destination chain', () => {
    const prepared = prepareBindRequest(PINS, validRequest());
    expect(prepared.chainId).toBe(84532n);
    expect(prepared.registry).toBe(REGISTRY);
    expect(prepared.account).toBe(ACCOUNT);
    expect(prepared.selfDestChainId).toBe(42220n);
    expect(prepared.nullifier).toBe(555n);
    expect(prepared.pubSignals[PASSPORT_DISCLOSE_INDEX.USER_IDENTIFIER]).toBe(
      calculateUserIdentifierHash(prepared.userContextData),
    );
  });

  it('formats the error message as CODE: detail for RPC consumers', () => {
    try {
      prepareBindRequest(PINS, validRequest({ registry: OTHER_ACCOUNT }));
    } catch (err) {
      expect((err as Error).message).toMatch(/^REGISTRY_NOT_ALLOWED: /);
      return;
    }
    throw new Error('expected a throw');
  });

  it('refuses malformed operator pins before looking at the request', () => {
    expect(codeOf(() => prepareBindRequest({ ...PINS, chainIdStr: 'base' }, validRequest()))).toBe('BAD_CHAIN_ID_VAR');
    expect(codeOf(() => prepareBindRequest({ ...PINS, allowedRegistryRaw: '0x12' }, validRequest()))).toBe(
      'BAD_REGISTRY_VAR',
    );
  });

  it('refuses a registry other than the pinned one', () => {
    expect(codeOf(() => prepareBindRequest(PINS, validRequest({ registry: OTHER_ACCOUNT })))).toBe(
      'REGISTRY_NOT_ALLOWED',
    );
  });

  it('refuses malformed addresses', () => {
    expect(codeOf(() => prepareBindRequest(PINS, validRequest({ registry: '0xnope' as Hex })))).toBe('BAD_REGISTRY');
    expect(codeOf(() => prepareBindRequest(PINS, validRequest({ account: '0x1' as Hex })))).toBe('BAD_ACCOUNT');
  });

  it('ties userContextData to the account and to signal 20', () => {
    // Context names a different account than the one requested.
    expect(
      codeOf(() => prepareBindRequest(PINS, validRequest({ userContextData: userContextData(OTHER_ACCOUNT) }))),
    ).toBe('USER_IDENTIFIER_MISMATCH');

    // Context names the right account but signal 20 was not derived from it.
    const req = validRequest();
    const tampered = [...req.pubSignals];
    tampered[PASSPORT_DISCLOSE_INDEX.USER_IDENTIFIER] = '1';
    expect(codeOf(() => prepareBindRequest(PINS, { ...req, pubSignals: tampered }))).toBe(
      'USER_IDENTIFIER_COMMITMENT_MISMATCH',
    );

    // Too short to hold both words.
    expect(codeOf(() => prepareBindRequest(PINS, validRequest({ userContextData: '0x1234' })))).toBe(
      'BAD_USER_CONTEXT_LENGTH',
    );
    expect(codeOf(() => prepareBindRequest(PINS, validRequest({ userContextData: 'abcd' as Hex })))).toBe(
      'BAD_USER_CONTEXT_FORMAT',
    );
  });

  it('keeps userDefinedData inside the commitment', () => {
    const ctx = userContextData(ACCOUNT, 42220n, '0x636f66666572646d'); // "cofferdm"
    const req = validRequest({ userContextData: ctx });
    // Signal 20 was computed over the empty-data context, so this must fail…
    expect(codeOf(() => prepareBindRequest(PINS, req))).toBe('USER_IDENTIFIER_COMMITMENT_MISMATCH');
    // …and pass once recomputed over the full preimage.
    const fixed = [...req.pubSignals];
    fixed[PASSPORT_DISCLOSE_INDEX.USER_IDENTIFIER] = calculateUserIdentifierHash(ctx).toString();
    expect(prepareBindRequest(PINS, { ...req, pubSignals: fixed }).selfDestChainId).toBe(42220n);
  });
});
