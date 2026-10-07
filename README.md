# cofferdam-attester

> Service-binding-only Worker that signs `NullifierRegistry.attesterMessageHash`
> with the registered `SelfAttester` ECDSA key. Part of the
> [Cofferdam](https://cofferdam.xyz) wallet stack.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The Cofferdam attester Worker holds the registered `SelfAttester` ECDSA key as
a Cloudflare-managed secret and signs bind messages that authorise
`NullifierRegistry` binds on Base. It is never publicly reachable — accessed
only via service-binding from
[`cofferdam-api`](https://github.com/cofferdamxyz/cofferdam-api). Trust model is
documented in
[cofferdam-sdk/IDENTITY_LAYER_DESIGN.md](https://github.com/cofferdamxyz/cofferdam-sdk/blob/main/IDENTITY_LAYER_DESIGN.md).

We do **not** generate Self proofs. Self.xyz already proves inside a GCP
Confidential Space enclave and already runs the Groth16 verifier plus identity
registry on Celo. This Worker's job is to bridge that Celo-side result onto
Base; there is no Cofferdam prover.

## Public RPC surface

```ts
interface AttesterRpc {
  signBind(req: {
    registry: `0x${string}`;
    account:  `0x${string}`;
    pubSignals: readonly string[];   // 21 decimal strings
    userContextData: `0x${string}`;  // >= 64 bytes, see below
  }): Promise<SignBindResponse>;

  // Testnet-only. Verifies the Self enclave's GCP Confidential Space
  // attestation before signing. See "Bind gates" below.
  signBindWithAttestation(req: {
    registry: `0x${string}`;
    account:  `0x${string}`;
    pubSignals: readonly string[];
    userContextData: `0x${string}`;
    attestation: string;             // GCP CS JWT, compact serialisation
  }): Promise<SignBindResponse & {
    enclaveImageDigest: string;      // sha256 hex, no prefix
    gate: 'attestation';
  }>;
}

type SignBindResponse = {
  attesterAddress: `0x${string}`;
  messageHash:     `0x${string}`;  // 32 bytes, attesterMessageHash preimage
  signature:       `0x${string}`;  // 65 bytes, EIP-191
  chainId:  string;
  registry: `0x${string}`;
  account:  `0x${string}`;
  userContextData: `0x${string}`;  // echoed; submit these exact bytes
};
```

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
- `SelfApp.chainID` **must** equal the registry's `selfDestChainId` immutable.

Source-of-truth: `src/rpc.ts`. Consumers duplicate this interface in
their own package; future `@cofferdam/types` will collapse the
duplication.

## Bind gates

`BIND_GATE_MODE` selects what evidence the attester demands before it
signs. The two modes are **not** equivalent in strength.

| Mode | Method | Verifies | Trusts the app? | Allowed on mainnet |
|---|---|---|---|---|
| `attestation` | `signBindWithAttestation` | GCP CS JWT chain + enclave image digest | **Yes** | No — hard-failed |
| `celo` | `signBind` | Groth16 proof + identity-commitment root via Celo `eth_call` | No | Yes |

### Why `attestation` is testnet-only

Self's attestation is a **channel-binding credential**, not a statement
about any proof. Their proving machine receives it during the WebSocket
handshake, derives an ECDH shared key from `eat_nonce[1]`, and only
*then* streams passport inputs to the enclave. The nullifier does not
exist when the JWT is signed.

So a valid attestation proves *"an allowlisted Self enclave image
offered this ECDH public key"* — not *"the nullifier in this request
came from that enclave"*. Only the holder of the derived shared key can
bridge those two, and that holder is the mobile app. A patched app can
pair a genuine attestation with a fabricated nullifier.

`src/index.ts` therefore refuses `signBindWithAttestation` outright when
`ENVIRONMENT=production`, independently of `BIND_GATE_MODE`.

### `SELF_TEE_IMAGE_DIGESTS`

The allowlist of accepted enclave measurements — sha256 hex of
`submods.container.image_digest`, comma/whitespace separated, `sha256:`
prefix optional. Self calls this value "PCR0" throughout their codebase;
that is legacy AWS Nitro naming retained after they migrated to GCP
Confidential Space, and it is not a PCR. Self's canonical list lives
on-chain in `PCR0Manager` at
`0xE36d4EE5Fd3916e703A46C21Bb3837dB7680C8B8` on Celo; we pin our own
copy so a Self-side addition cannot silently widen what this attester
accepts.

Capture the current digest from a device run of the Self NFC smoke test
— the Success screen prints it under **TEE Proving Session → Enclave
(GCP CS)**. Empty is tolerated only when `ENVIRONMENT=development`,
which also relaxes the `dbgstat` debug-disabled requirement.

Expect this list to hold more than one entry during a Self enclave
rollout. A spike of `ATT_IMAGE_DIGEST_NOT_ALLOWED` in
`wrangler tail` is the signal that Self rotated images.

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

`onchainValid: true` proves the whole rail: service binding → attester key signs the
canonical preimage → `SelfAttesterRegistry.verifyAttesterSig` recovers that address
on Base Sepolia and finds it allow-listed. Drop `| jq '.onchainValid'` to inspect
`userContextData` and the derived `pubSignals[20]` commitment.

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

## Responsibilities (per IDENTITY_LAYER_DESIGN.md §3, step 7)

1. Receive `(account, registry, pubSignals, userContextData)` from a bound
   caller.
2. Validate `registry` against the pinned allowlist (single-element
   in α: `NULLIFIER_REGISTRY_ADDRESS` from `wrangler.jsonc`).
3. Decode `userContextData`, require the embedded user id to equal
   `account`, and require `ripemd160(sha256(userContextData))` to equal
   `pubSignals[USER_IDENTIFIER]`. Fail-fast mirror of the on-chain check.
4. Recompute `attesterMessageHash(chainId, registry, account, pubSignals)`
   byte-for-byte with `NullifierRegistry.attesterMessageHash`.
5. Sign with EIP-191 personal_sign over the 32-byte hash.
6. Return `{ attesterAddress, messageHash, signature, userContextData }`
   plus echoed audit fields.
7. Rotate the signing key quarterly + on incident. On rotation, the
   new attester address is registered via
   `SelfAttesterRegistry.addAttester(...)` on Base; the old one
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
| [`cofferdam-api`](https://github.com/cofferdamxyz/cofferdam-api)     | Public-edge HTTP Worker; consumes this RPC    |
| [`cofferdam-sdk`](https://github.com/cofferdamxyz/cofferdam-sdk)     | Public SDK + identity-layer design doc        |
| [`base-contracts`](https://github.com/cofferdamxyz/base-contracts)   | Solidity contracts (Self.xyz integration)     |

## License

[Apache License 2.0](LICENSE). Copyright 2026 Cofferdam Inc.
