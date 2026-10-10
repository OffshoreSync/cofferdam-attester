# cofferdam-attester

> Service-binding-only Worker that signs `NullifierRegistry.attesterMessageHash`
> with the registered `SelfAttester` ECDSA key — after re-verifying the proof
> against Self.xyz's registry on Celo. Part of the
> [Cofferdam](https://cofferdam.xyz) wallet stack.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The Cofferdam attester Worker holds the registered `SelfAttester` ECDSA key as
a Cloudflare-managed secret and signs bind messages that authorise
`NullifierRegistry.verifyAndBind` on Base. It is never publicly reachable —
accessed only via service binding from
[`cofferdam-api`](https://github.com/cofferdamxyz/cofferdam-api). Trust model is
documented in
[cofferdam-sdk/IDENTITY_LAYER_DESIGN.md](https://github.com/cofferdamxyz/cofferdam-sdk/blob/main/IDENTITY_LAYER_DESIGN.md)
and the gate design in `Cofferdam/decisions/0004`.

We do **not** generate Self proofs. Self.xyz proves inside a GCP Confidential
Space enclave and anchors the identity-commitment tree, the OFAC roots and the
Groth16 verifiers on Celo. This Worker bridges that Celo-side state onto Base;
there is no Cofferdam prover.

## Public RPC surface

```ts
interface AttesterRpc {
  signBind(req: {
    registry: `0x${string}`;
    account:  `0x${string}`;
    pubSignals: readonly string[];   // 21 decimal strings
    userContextData: `0x${string}`;  // >= 64 bytes, see below
  }): Promise<SignBindResponse>;
}

type SignBindResponse = {
  attesterAddress: `0x${string}`;
  messageHash:     `0x${string}`;  // 32 bytes, attesterMessageHash preimage
  signature:       `0x${string}`;  // 65 bytes, EIP-191
  chainId:  string;
  registry: `0x${string}`;
  account:  `0x${string}`;
  userContextData: `0x${string}`;  // echoed; submit these exact bytes
  gate: 'celo';
  celo: {
    chainId: string;                 // "42220"
    registry: `0x${string}`;         // Self's E_PASSPORT identity registry
    merkleRoot: string;              // pubSignals[9], confirmed published
    proofDate: string;               // "YYYY-MM-DD" from pubSignals[10..15]
  };
};
```

Errors are thrown with a `CODE: detail` message so consumers can branch on
the prefix over Workers RPC. Request-shape codes come from `src/bind.ts`
(`REGISTRY_NOT_ALLOWED`, `USER_IDENTIFIER_MISMATCH`, …); gate codes from
`src/celoGate.ts` (`CELO_ROOT_UNKNOWN`, `CELO_OFAC_ROOTS_STALE`,
`PROOF_DATE_OUT_OF_WINDOW`, …). Only `CELO_RPC_UNAVAILABLE` is retryable.

Source of truth: `src/rpc.ts`. `cofferdam-api/src/services/attester.ts` keeps a
byte-compatible copy; change both in the same commit.

### `userContextData` — why signal 20 is not the address

The `vc_and_disclose` circuit's `userIdentifier` public signal (index 20) is
**not** `uint160(account)`. Self emits a 160-bit commitment:

```
userContextData = abi.encodePacked(
    bytes32(SelfApp.chainID),   // Self's declared dest chain (Celo 42220)
    bytes32(userId),            // left-padded; hyphens stripped
    bytes(userDefinedData))     // raw UTF-8, may be empty

userIdentifier  = uint160(ripemd160(sha256(userContextData)))
```

see `calculateUserIdentifierHash` in `self/common/src/utils/hash.ts`.

The attester therefore requires the preimage: it decodes the embedded user id,
requires it to equal `account`, and recomputes the commitment against
`pubSignals[20]`. `NullifierRegistry.verifyAndBind` takes the same bytes and
re-runs both checks on-chain via the `sha256`/`ripemd160` precompiles, so the
attester's version is purely a fail-fast that saves gas.

Two consequences for callers:

- `SelfApp.userId` **must** be the AA address. A UUID produces a valid proof
  that can never bind.
- `SelfApp.chainID` **must** equal the registry's `selfDestChainId` immutable
  (and this Worker's `SELF_CELO_CHAIN_ID`).

## The Celo gate

Base's `NullifierRegistry` verifies the Groth16 proof itself, but a Groth16
proof only shows "this commitment is a leaf of the tree with root R". It cannot
show that R is one of Self's roots: a forged tree yields a perfectly valid
proof over an invented commitment. The attester is where that gap closes.
Before it signs, `src/celoGate.ts` asks Celo over read-only `eth_call` the same
questions `IdentityVerificationHubImplV2._basicVerification` asks when a proof
is consumed natively:

| Check | Celo call | Rejection code |
|---|---|---|
| Hub still routes E_PASSPORT to the pinned registry | `hub.registry(bytes32(1))` | `CELO_REGISTRY_MISMATCH` |
| Proof's Merkle root was published by Self | `registry.checkIdentityCommitmentRoot(pubSignals[9])` | `CELO_ROOT_UNKNOWN` |
| Proof used the current or previous OFAC snapshot | `registry.checkOfacRoots(pubSignals[16], [17], [18])` | `CELO_OFAC_ROOTS_STALE` |
| RPC answers for the pinned chain | `eth_chainId` | `CELO_CHAIN_MISMATCH` |
| Proof date (`pubSignals[10..15]`, YYMMDD) within ±1 day UTC | — | `PROOF_DATE_OUT_OF_WINDOW` |
| Attestation id is E_PASSPORT | — | `WRONG_ATTESTATION_ID` |
| `userContextData` destination chain equals the pinned Celo | — | `WRONG_DEST_CHAIN_ID` |

Roots never expire on Self's registry, so the root check is membership over
every root ever published, exactly as on Celo. The Groth16 proof is not
re-verified here: the attester signs over the public signals only, so a
tampered proof reverts on Base rather than being accepted off-chain.

Pins live in `wrangler.jsonc`: `CELO_RPC_URL`, `SELF_CELO_CHAIN_ID`,
`SELF_HUB_ADDRESS`, `SELF_PASSPORT_REGISTRY_ADDRESS`. They change only when
Self migrates contracts — a spike of `CELO_REGISTRY_MISMATCH` in
`wrangler tail` is that signal. Self's staging stack (Celo Sepolia, mock
passports) cannot be used with the current registry because
`selfDestChainId = 42220` is immutable on Base.

## Local dev

```bash
yarn install

# Set the attester private key as a local-dev secret. Stored in
# `.dev.vars` (already git-ignored).
echo "ATTESTER_PRIVATE_KEY=0x<paste-from-1Password>" > .dev.vars

yarn dev
# wrangler dev binds on a high port, prints the local-registry URL.
# Leave running; cofferdam-api/yarn dev will auto-discover it.
```

Local dev reads Celo mainnet through the same public RPC as production; no
local chain is involved.

## Tests

```bash
yarn test              # unit: gate, request validation, signing (fixtures)
CELO_LIVE=1 yarn test  # also runs the gate against forno.celo.org
```

The live test reads the current root and OFAC roots from Celo and proves the
viem-backed reads agree with the fixture semantics; it is skipped by default
so CI stays offline.

## Deploy

```bash
yarn install

# Upload the attester key as a Cloudflare-managed secret. Wrangler
# will prompt; paste from 1Password. Encrypted at rest in Cloudflare's
# secret store; never visible in dashboards or wrangler tail.
yarn wrangler secret put ATTESTER_PRIVATE_KEY

# Deploy. workers_dev:false means there is no public URL; the only
# way to reach this Worker is via the service binding declared on
# cofferdam-api.
yarn deploy
```

After deploy, smoke-test from `cofferdam-api` (which has the binding):

```bash
# Substitute your own workers.dev subdomain — `wrangler deploy` prints the
# full URL under "Deployed cofferdam-api triggers".
API="https://cofferdam-api.<your-subdomain>.workers.dev"

curl -sX POST "$API/v1/attester/test-sign" \
  -H 'content-type: application/json' \
  -d '{"account":"0xfa4D920d5592289A1A0F73CA49D626EF8FE4D695"}' | jq '.onchainValid'
# expect: true
```

If this prints **nothing at all**, the placeholder was not substituted: `curl -s`
swallows the DNS failure and `jq` then receives empty input. Re-run without `-s`
(and without the `jq` pipe) to see the real error.

`test-sign` builds synthetic public signals that carry Celo's *current* root and
OFAC roots plus today's date, so the request passes the gate without a proof;
nothing can be bound with it because there is no Groth16 proof behind the
signals. `onchainValid: true` proves the whole rail: service binding → Celo
gate → attester key signs the canonical preimage →
`SelfAttesterRegistry.verifyAttesterSig` recovers that address on Base Sepolia
and finds it allow-listed. Drop `| jq '.onchainValid'` to inspect
`signed.celo` and the derived `pubSignals[20]` commitment.

This Worker has `workers_dev: false` and no routes, so it has **no public URL** of its
own — `wrangler deploy` correctly reports "No deploy targets". It is only reachable
through the `ATTESTER` service binding on `cofferdam-api`.

## Local development

Two `wrangler dev` sessions; the dev registry wires the service binding
automatically. The attester needs an explicit port because `cofferdam-api`
already owns the default `8787`:

```bash
yarn --cwd cofferdam-attester wrangler dev --port 8788
yarn --cwd cofferdam-api dev     # --ip 0.0.0.0, port 8787
```

`cofferdam-api` should log `env.ATTESTER (cofferdam-attester) Worker local [connected]`.
Then the same `test-sign` call works against `http://127.0.0.1:8787`.

### After rotating the attester key, update `.dev.vars` too

`wrangler secret put` only writes the **deployed** secret. Local dev reads
`ATTESTER_PRIVATE_KEY` from `cofferdam-attester/.dev.vars`, which a rotation
leaves untouched — so local signatures keep using the retired key and
`onchainValid` is `false` while the deployed Worker is fine.

The symptom is specific: the response's `signed.attesterAddress` is an address
that `SelfAttesterRegistry.isTrustedAttester` returns `false` for.

```bash
# which key is local dev actually using?
curl -sX POST http://127.0.0.1:8787/v1/attester/test-sign \
  -H 'content-type: application/json' \
  -d '{"account":"0xfa4D920d5592289A1A0F73CA49D626EF8FE4D695"}' \
  | jq '{onchainValid, signer: .signed.attesterAddress}'
```

If `signer` is not the registered attester, paste the rotated key into
`.dev.vars` and restart the dev session. `.dev.vars` is gitignored; the key
lives in 1Password.

## Responsibilities

1. Receive `(account, registry, pubSignals, userContextData)` from a bound
   caller.
2. Validate `registry` against the pinned allowlist (single-element:
   `NULLIFIER_REGISTRY_ADDRESS` from `wrangler.jsonc`).
3. Decode `userContextData`, require the embedded user id to equal
   `account`, and require `ripemd160(sha256(userContextData))` to equal
   `pubSignals[USER_IDENTIFIER]`. Fail-fast mirror of the on-chain check.
4. Run the Celo gate (table above). Refuse on any mismatch; never sign a
   proof whose root Self did not publish.
5. Recompute `attesterMessageHash(chainId, registry, account, pubSignals)`
   byte-for-byte with `NullifierRegistry.attesterMessageHash`.
6. Sign with EIP-191 personal_sign over the 32-byte hash.
7. Return `{ attesterAddress, messageHash, signature, userContextData, celo }`
   plus echoed audit fields, and log one audit line per sign or rejection.
8. Rotate the signing key quarterly + on incident. On rotation, the
   new attester address is registered via
   `SelfAttesterRegistry.addAttester(...)` on Base; the old one
   is removed after a cooldown window.

## Why a separate Worker

- **Blast radius isolation.** The attester key is the production
  identity rail. A bug in `cofferdam-api` cannot expose it because
  `cofferdam-api` only calls `signBind(...)` via service binding —
  it never sees the raw secret. The Worker's only egress is the read-only
  Celo RPC.
- **Independent audit log.** Every signature and every gate rejection is
  logged; an audit job replays sign events against on-chain
  `NullifierBound` events to detect any over-signing.
- **Contract-free rotation.** Replacing the attester key is an
  `addAttester` / `removeAttester` pair on `SelfAttesterRegistry`; nothing
  else on-chain moves.

## Sibling repositories

| Repo                                                                 | Role                                          |
|----------------------------------------------------------------------|-----------------------------------------------|
| [`cofferdam-api`](https://github.com/cofferdamxyz/cofferdam-api)     | Public-edge HTTP Worker; consumes this RPC    |
| [`cofferdam-sdk`](https://github.com/cofferdamxyz/cofferdam-sdk)     | Public SDK + identity-layer design doc        |
| [`base-contracts`](https://github.com/cofferdamxyz/base-contracts)   | Solidity contracts (Self.xyz integration)     |

## License

[Apache License 2.0](LICENSE). Copyright 2026 Cofferdam Inc.
