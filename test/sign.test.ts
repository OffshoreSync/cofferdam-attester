// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { recoverMessageAddress, type Hex } from 'viem';

import {
  attesterMessageHash,
  calculateUserIdentifierHash,
  decodeUserContextData,
  signBindAttestation,
} from '../src/sign.js';

// Known-answer vectors pinned 2026-10-10 against viem 2.51.3. If these move,
// the on-chain `NullifierRegistry.attesterMessageHash` no longer matches.
const REGISTRY: Hex = '0x2843F55C9E1491a6d47F65f041E68F96E3aeB3d4';
const ACCOUNT: Hex = '0xfa4D920d5592289A1A0F73CA49D626EF8FE4D695';
const CTX: Hex =
  '0x000000000000000000000000000000000000000000000000000000000000a4ec000000000000000000000000fa4d920d5592289a1a0f73ca49d626ef8fe4d695';
const USER_IDENTIFIER = 485990643273764334479787657733009101342132995857n;
const EXPECTED_HASH: Hex = '0xf8a5b5fa592eb9dc3aa63dcb728b72dafe56ced6a909318064e85daa54977050';
const TEST_KEY: Hex = `0x${'11'.repeat(32)}`;
const TEST_SIGNER: Hex = '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A';

function vectorPubSignals(): bigint[] {
  const s = Array.from({ length: 21 }, (_, i) => BigInt(i));
  s[20] = USER_IDENTIFIER;
  return s;
}

describe('userContextData helpers', () => {
  it('decodes the destination chain and the embedded account', () => {
    expect(decodeUserContextData(CTX)).toEqual({ destChainId: 42220n, userId: ACCOUNT });
  });

  it('recomputes the userIdentifier commitment Self emits as signal 20', () => {
    expect(calculateUserIdentifierHash(CTX)).toBe(USER_IDENTIFIER);
  });

  it('rejects preimages shorter than the two fixed words', () => {
    expect(() => decodeUserContextData('0x00')).toThrowError(/at least 64 bytes/);
  });
});

describe('attesterMessageHash', () => {
  it('matches the pinned keccak256(abi.encode(chainId, registry, account, uint256[21])) vector', () => {
    expect(
      attesterMessageHash({ chainId: 84532n, registry: REGISTRY, account: ACCOUNT, pubSignals: vectorPubSignals() }),
    ).toBe(EXPECTED_HASH);
  });

  it('changes with every input', () => {
    const base = { chainId: 84532n, registry: REGISTRY, account: ACCOUNT, pubSignals: vectorPubSignals() };
    expect(attesterMessageHash({ ...base, chainId: 8453n })).not.toBe(EXPECTED_HASH);
    expect(attesterMessageHash({ ...base, account: REGISTRY })).not.toBe(EXPECTED_HASH);
    const s = vectorPubSignals();
    s[7] = 8n;
    expect(attesterMessageHash({ ...base, pubSignals: s })).not.toBe(EXPECTED_HASH);
  });

  it('refuses malformed inputs', () => {
    expect(() =>
      attesterMessageHash({ chainId: 1n, registry: REGISTRY, account: ACCOUNT, pubSignals: [1n] }),
    ).toThrowError(/length must be 21/);
    expect(() =>
      attesterMessageHash({ chainId: 1n, registry: '0x12' as Hex, account: ACCOUNT, pubSignals: vectorPubSignals() }),
    ).toThrowError(/registry/);
  });
});

describe('signBindAttestation', () => {
  it('produces an EIP-191 signature that recovers to the key address', async () => {
    const signed = await signBindAttestation(TEST_KEY, {
      chainId: 84532n,
      registry: REGISTRY,
      account: ACCOUNT,
      pubSignals: vectorPubSignals(),
    });
    expect(signed.attesterAddress).toBe(TEST_SIGNER);
    expect(signed.messageHash).toBe(EXPECTED_HASH);
    expect(signed.signature).toMatch(/^0x[0-9a-f]{130}$/);
    const v = Number.parseInt(signed.signature.slice(-2), 16);
    expect([27, 28]).toContain(v);
    await expect(
      recoverMessageAddress({ message: { raw: signed.messageHash }, signature: signed.signature }),
    ).resolves.toBe(TEST_SIGNER);
  });
});
