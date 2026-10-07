// Copyright (c) 2026 Cofferdam Inc
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
  getAddress,
  isAddress,
  keccak256,
  ripemd160,
  sha256,
  size,
  slice,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

/**
 * Recompute Self's `userIdentifier` public signal from its preimage.
 *
 * The `vc_and_disclose` circuit does NOT emit the user's address in signal
 * 20 — it emits a 160-bit commitment:
 *
 *     userContextData = abi.encodePacked(
 *         bytes32(destChainID),   // SelfApp.chainID, left-padded
 *         bytes32(userId),        // left-padded, hyphens stripped
 *         bytes(userDefinedData))
 *     userIdentifier  = uint160(ripemd160(sha256(userContextData)))
 *
 * Mirrors `calculateUserIdentifierHash` in `self/common/src/utils/hash.ts`
 * and `NullifierRegistry._checkUserContext` on-chain.
 */
export function calculateUserIdentifierHash(userContextData: Hex): bigint {
  return BigInt(ripemd160(sha256(userContextData)));
}

/** Fields the registry slices out of `userContextData`. */
export interface DecodedUserContext {
  /** Self's declared destination chain (`SelfApp.chainID`), not the host chain. */
  readonly destChainId: bigint;
  /** The embedded user id, narrowed to an address. */
  readonly userId: Hex;
}

/**
 * Decode the fixed 64-byte head of `userContextData`. Throws if the payload
 * is too short to contain both words.
 */
export function decodeUserContextData(userContextData: Hex): DecodedUserContext {
  if (size(userContextData) < 64) {
    throw new Error(
      `userContextData must be at least 64 bytes, got ${size(userContextData)}`,
    );
  }
  return {
    destChainId: BigInt(slice(userContextData, 0, 32)),
    // Self left-pads the id to 32 bytes; the low 20 are the address.
    userId: getAddress(slice(userContextData, 44, 64)),
  };
}

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
