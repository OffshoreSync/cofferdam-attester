// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * Request validation for `signBind`, kept free of Cloudflare globals so it
 * unit-tests in Node.
 *
 * Everything here is a fail-fast mirror of what `NullifierRegistry.verifyAndBind`
 * enforces on Base (pinned chain, pinned registry, 21 well-formed public
 * signals, `userContextData` naming the account and hashing to signal 20).
 * The Celo gate (`celoGate.ts`) runs after this and is the check the chain
 * cannot do itself.
 */

import { getAddress, isAddress, type Hex } from 'viem';
import { PASSPORT_DISCLOSE_INDEX, PUB_SIGNALS_LENGTH } from './celoGate.js';
import type { SignBindRequest } from './rpc.js';
import {
  calculateUserIdentifierHash,
  decodeUserContextData,
  type DecodedUserContext,
} from './sign.js';

/** Max value of a uint256 — sanity bound for incoming pubSignals. */
const UINT256_MAX = (1n << 256n) - 1n;

/**
 * Domain error surfaced over Workers RPC. The runtime serialises thrown
 * errors by `message`, so the code is folded into it as a `CODE: detail`
 * prefix that consumers can branch on; `code` stays available in-process.
 */
export class AttesterError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    /** True when retrying the same request may succeed (RPC hiccup). */
    public readonly retryable = false,
  ) {
    super(`${code}: ${message}`);
    this.name = 'AttesterError';
  }
}

export function badRequest(code: string, message: string): never {
  throw new AttesterError(code, message);
}

export function parsePubSignals(raw: readonly string[]): bigint[] {
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

/** Deploy-time pins the attester refuses to sign outside of. */
export interface BindPins {
  /** `BASE_CHAIN_ID` var, decimal string. */
  readonly chainIdStr: string;
  /** `NULLIFIER_REGISTRY_ADDRESS` var. */
  readonly allowedRegistryRaw: string;
}

export interface PreparedBind {
  readonly chainId: bigint;
  readonly chainIdStr: string;
  readonly registry: Hex;
  readonly account: Hex;
  readonly pubSignals: readonly bigint[];
  readonly userContextData: Hex;
  /** Self's declared destination chain, decoded from `userContextData`. */
  readonly selfDestChainId: bigint;
  readonly nullifier: bigint;
}

/**
 * Validate a `signBind` request against the deploy-time pins. Throws
 * `AttesterError`; performs no I/O and never touches the signing key.
 */
export function prepareBindRequest(pins: BindPins, req: SignBindRequest): PreparedBind {
  // ── Pinned values from env ──────────────────────────────────────
  if (!/^\d+$/.test(pins.chainIdStr)) {
    throw new AttesterError('BAD_CHAIN_ID_VAR', `BASE_CHAIN_ID var is malformed: ${pins.chainIdStr}`);
  }
  const chainId = BigInt(pins.chainIdStr);

  if (!isAddress(pins.allowedRegistryRaw)) {
    throw new AttesterError(
      'BAD_REGISTRY_VAR',
      `NULLIFIER_REGISTRY_ADDRESS var is malformed: ${pins.allowedRegistryRaw}`,
    );
  }
  const allowedRegistry = getAddress(pins.allowedRegistryRaw);

  // ── Request shape ───────────────────────────────────────────────
  if (!req || typeof req !== 'object') {
    badRequest('BAD_REQUEST', 'request body is missing or not an object');
  }
  if (typeof req.registry !== 'string' || !isAddress(req.registry)) {
    badRequest('BAD_REGISTRY', 'request.registry is not a valid address');
  }
  if (typeof req.account !== 'string' || !isAddress(req.account)) {
    badRequest('BAD_ACCOUNT', 'request.account is not a valid address');
  }
  const registry = getAddress(req.registry);
  const account = getAddress(req.account);

  // ── Pinned-registry allowlist ───────────────────────────────────
  if (registry !== allowedRegistry) {
    badRequest(
      'REGISTRY_NOT_ALLOWED',
      `attester refuses to sign for registry ${registry}; pinned registry is ${allowedRegistry}`,
    );
  }

  const pubSignals = parsePubSignals(req.pubSignals);

  // ── userContextData ↔ account ↔ signal 20 ───────────────────────
  // Signal 20 is NOT uint160(account): Self emits
  // ripemd160(sha256(userContextData)), so the only way to tie the proof
  // to `account` is to recompute that commitment and inspect the id in
  // the preimage. The registry re-runs both checks on-chain.
  const userContextData = req.userContextData;
  if (typeof userContextData !== 'string' || !/^0x[0-9a-fA-F]*$/.test(userContextData)) {
    badRequest('BAD_USER_CONTEXT_FORMAT', 'userContextData must be a 0x-prefixed hex string');
  }

  let decoded: DecodedUserContext;
  try {
    decoded = decodeUserContextData(userContextData);
  } catch (err) {
    badRequest(
      'BAD_USER_CONTEXT_LENGTH',
      err instanceof Error ? err.message : 'userContextData is malformed',
    );
  }

  if (getAddress(decoded.userId) !== account) {
    badRequest(
      'USER_IDENTIFIER_MISMATCH',
      `userContextData names ${decoded.userId}, not the requested account ${account}`,
    );
  }

  const expectedUserIdentifier = calculateUserIdentifierHash(userContextData);
  const userIdentifier = pubSignals[PASSPORT_DISCLOSE_INDEX.USER_IDENTIFIER]!;
  if (userIdentifier !== expectedUserIdentifier) {
    badRequest(
      'USER_IDENTIFIER_COMMITMENT_MISMATCH',
      `pubSignals[USER_IDENTIFIER] (${userIdentifier}) does not match the commitment over ` +
        `userContextData (${expectedUserIdentifier})`,
    );
  }

  return {
    chainId,
    chainIdStr: pins.chainIdStr,
    registry,
    account,
    pubSignals,
    userContextData,
    selfDestChainId: decoded.destChainId,
    nullifier: pubSignals[PASSPORT_DISCLOSE_INDEX.NULLIFIER]!,
  };
}
