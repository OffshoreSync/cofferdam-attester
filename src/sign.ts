// Copyright (c) 2026 OffshoreSync LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Pure crypto module for the Self attester.
 *
 * Reproduces `NullifierRegistry.attesterMessageHash(account, pubSignals)`
 * byte-for-byte and signs it with EIP-191 personal_sign so the resulting
 * 65-byte signature is consumable by `SelfAttesterRegistry.verifyAttesterSig`
 * on-chain. Kept dependency-free of Cloudflare globals so the same code
 * can be unit-tested in Node.
 *
 * On-chain preimage (see contracts/v2/self/NullifierRegistry.sol:208-216):
 *
 *     keccak256(abi.encode(
 *         block.chainid,         // uint256
 *         address(this),         // address (NullifierRegistry)
 *         account,               // address (target account being bound)
 *         pubSignals             // uint256[21] (static array, encoded inline)
 *     ))
 *
 * `uint256[21]` is a static array per Solidity ABI: encoded as 21 contiguous
 * 32-byte slots, with no length prefix or offset. viem's `encodeAbiParameters`
 * with type `'uint256[21]'` matches this exactly.
 */

import {
  encodeAbiParameters,
  isAddress,
  keccak256,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

/**
 * Compile-time fixed-length tuple. Used to satisfy viem's
 * `uint256[21]` parameter, which it types as a 21-element bigint
 * tuple rather than `bigint[]`.
 */
type FixedTuple<T, N extends number, A extends T[] = []> = A['length'] extends N
  ? A
  : FixedTuple<T, N, [T, ...A]>;

export type PubSignalsTuple = FixedTuple<bigint, 21>;

export interface BindAttestationInputs {
  /** Chain ID as bigint (e.g. `300n` for ZKSync Era Sepolia). */
  readonly chainId: bigint;
  /** EIP-55 address of the target `NullifierRegistry`. */
  readonly registry: Hex;
  /** EIP-55 address of the account being bound. */
  readonly account: Hex;
  /** 21 public signals from the `vc_and_disclose` proof. */
  readonly pubSignals: readonly bigint[];
}

export interface SignedBindAttestation {
  /** Recovered address of the signer (sanity-check vs. on-chain allowlist). */
  readonly attesterAddress: Hex;
  /** Raw 32-byte hash signed (matches `NullifierRegistry.attesterMessageHash`). */
  readonly messageHash: Hex;
  /** 65-byte EIP-191 personal_sign signature (r,s,v) with v in {27,28}. */
  readonly signature: Hex;
}

/**
 * Reproduces `NullifierRegistry.attesterMessageHash` off-chain. Throws
 * synchronously on malformed input; callers should validate before
 * surfacing errors to clients.
 */
export function attesterMessageHash(inputs: BindAttestationInputs): Hex {
  if (!isAddress(inputs.registry)) {
    throw new Error(`registry is not a valid address: ${inputs.registry}`);
  }
  if (!isAddress(inputs.account)) {
    throw new Error(`account is not a valid address: ${inputs.account}`);
  }
  if (inputs.pubSignals.length !== 21) {
    throw new Error(
      `pubSignals length must be 21, got ${inputs.pubSignals.length}`,
    );
  }

  const encoded = encodeAbiParameters(
    [
      { type: 'uint256' },
      { type: 'address' },
      { type: 'address' },
      { type: 'uint256[21]' },
    ],
    [
      inputs.chainId,
      inputs.registry,
      inputs.account,
      inputs.pubSignals as unknown as PubSignalsTuple,
    ],
  );
  return keccak256(encoded);
}

/**
 * Sign a bind attestation with EIP-191 personal_sign.
 *
 * viem's `signMessage({ message: { raw } })` applies the
 * `\x19Ethereum Signed Message:\n32` prefix and returns a 65-byte
 * signature with low-s and v in {27, 28} — exactly what
 * `SelfAttesterRegistry._recover` expects.
 */
export async function signBindAttestation(
  privateKey: Hex,
  inputs: BindAttestationInputs,
): Promise<SignedBindAttestation> {
  const account = privateKeyToAccount(privateKey);
  const messageHash = attesterMessageHash(inputs);
  const signature = await account.signMessage({
    message: { raw: messageHash },
  });
  return {
    attesterAddress: account.address,
    messageHash,
    signature,
  };
}
