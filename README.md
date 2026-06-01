# cofferdam-attester

> Service-binding-only Worker that signs `NullifierRegistry.attesterMessageHash`
> with the registered `SelfAttester` ECDSA key. Part of the
> [Cofferdam](https://cofferdam.xyz) wallet stack.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The Cofferdam attester Worker holds the registered `SelfAttester` ECDSA key as
a Cloudflare-managed secret and signs bind messages emitted by
[`cofferdam-prover`](https://github.com/OffshoreSync/cofferdam-prover). It is
never publicly reachable — accessed only via service-binding from
[`cofferdam-api`](https://github.com/OffshoreSync/cofferdam-api) and
`cofferdam-prover`. Trust model is documented in
[cofferdam-sdk/IDENTITY_LAYER_DESIGN.md](https://github.com/OffshoreSync/cofferdam-sdk/blob/main/IDENTITY_LAYER_DESIGN.md).

## Public RPC surface

```ts
interface AttesterRpc {
  signBind(req: {
    registry: `0x${string}`;
    account:  `0x${string}`;
    pubSignals: readonly string[];   // 21 decimal strings
  }): Promise<{
    attesterAddress: `0x${string}`;
    messageHash:     `0x${string}`;
    signature:       `0x${string}`;  // 65 bytes, EIP-191
    chainId:  string;
    registry: `0x${string}`;
    account:  `0x${string}`;
  }>;
}
```

Source-of-truth: `src/rpc.ts`. Consumers duplicate this interface in
their own package; future `@cofferdam/types` will collapse the
duplication.

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

## Deploy

```bash
yarn install

# Upload the attester key as a Cloudflare-managed secret. Wrangler
# will prompt; paste from 1Password. Encrypted at rest in Cloudflare's
# secret store; never visible in dashboards or wrangler tail.
yarn wrangler secret put ATTESTER_PRIVATE_KEY

# Deploy. workers_dev:false means there is no public URL; the only
# way to reach this Worker is via the service binding declared on
# cofferdam-api (and, in Sessions 4-5, cofferdam-prover).
yarn deploy
```

After deploy, smoke-test from `cofferdam-api` (which has the binding):

```bash
curl -sX POST https://cofferdam-api.<subdomain>.workers.dev/v1/attester/test-sign \
  -H 'content-type: application/json' \
  -d '{"account":"0xfa4D920d5592289A1A0F73CA49D626EF8FE4D695"}' | jq '.onchainValid'
# expect: true
```

## Responsibilities (per IDENTITY_LAYER_DESIGN.md §3, step 7)

1. Receive `(account, registry, pubSignals)` from a bound caller.
2. Validate `registry` against the pinned allowlist (single-element
   in α: `NULLIFIER_REGISTRY_ADDRESS` from `wrangler.jsonc`).
3. Recompute `attesterMessageHash(chainId, registry, account, pubSignals)`
   byte-for-byte with `NullifierRegistry.attesterMessageHash`.
4. Sign with EIP-191 personal_sign over the 32-byte hash.
5. Return `{ attesterAddress, messageHash, signature }` plus echoed
   audit fields.
6. Rotate the signing key quarterly + on incident. On rotation, the
   new attester address is registered via
   `SelfAttesterRegistry.addAttester(...)` on ZKSync Era; the old one
   is removed after a cooldown window.

## Why a separate Worker

- **Blast radius isolation.** The attester key is the production
  identity rail. A bug in `cofferdam-api` cannot expose it because
  `cofferdam-api` only calls `attester.sign(...)` via service binding —
  it never sees the raw secret.
- **Independent audit log.** Every attester signature is logged with a
  monotonic counter; an audit job replays the counter against
  on-chain `NullifierBound` events to detect any over-signing.
- **Future TEE upgrade path.** Replacing the attester key with a
  TEE-attested key (Phase γ) is a single-Worker swap — the
  `SelfAttesterRegistry.addAttester` rotation primitive makes the
  migration contract-free per `IDENTITY_LAYER_DESIGN.md` §8.

## Sibling repositories

| Repo                                                                 | Role                                          |
|----------------------------------------------------------------------|-----------------------------------------------|
| [`cofferdam-api`](https://github.com/OffshoreSync/cofferdam-api)     | Public-edge HTTP Worker; consumes this RPC    |
| [`cofferdam-prover`](https://github.com/OffshoreSync/cofferdam-prover) | Self.xyz Groth16 prover Container (WIP)     |
| [`cofferdam-sdk`](https://github.com/OffshoreSync/cofferdam-sdk)     | Public SDK + identity-layer design doc        |
| [`contracts`](https://github.com/OffshoreSync/contracts)             | Solidity contracts (Self.xyz integration)     |

## License

[Apache License 2.0](LICENSE). Copyright 2026 OffshoreSync LLC.
