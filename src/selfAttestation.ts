// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * GCP Confidential Space attestation verification for the Cofferdam
 * Self attester.
 *
 * ## What this verifies
 *
 * Self.xyz generates every ZK proof inside a **GCP Confidential Space**
 * enclave — NOT an AWS Nitro enclave. The enclave publishes an RS256
 * JWT signed by a leaf certificate that chains to Google's
 * "Confidential Space Root CA". Self's own client-side check lives at
 * `self/common/src/utils/attest.ts::validatePKIToken`; this module is a
 * dependency-free Workers port of the same logic, plus the extra
 * validation Self omits (validity windows, `exp`/`nbf`, issuer linkage).
 *
 * The JWT payload carries:
 *   - `submods.container.image_digest` — the enclave image measurement,
 *     prefixed `sha256:`. Self calls this "PCR0" throughout their
 *     codebase, which is legacy AWS Nitro naming; it is not a PCR.
 *   - `eat_nonce[0]` — the CLIENT's ephemeral ECDH public key.
 *   - `eat_nonce[1]` — the ENCLAVE's ephemeral ECDH public key.
 *   - `dbgstat` — must be `disabled-since-boot` outside dev.
 *
 * ## What this does NOT verify — read before trusting it
 *
 * The attestation is a **channel-binding credential, not a statement
 * about any proof**. Self's proving machine receives it during the
 * WebSocket handshake, derives an ECDH shared key from
 * `eat_nonce[1]`, and only then streams passport inputs to the enclave
 * (see `self/packages/mobile-sdk-alpha/src/proving/provingMachine.ts`
 * `_handleWebSocketMessage`). The nullifier does not exist yet at the
 * moment this JWT is signed.
 *
 * Therefore a valid attestation proves:
 *   "an allowlisted Self enclave image offered this ECDH public key"
 *
 * and NOT:
 *   "the nullifier accompanying this request came from that enclave"
 *
 * Only the holder of the derived shared key can bridge that gap, and
 * that holder is the mobile app. A patched app can present a genuine
 * attestation alongside a fabricated nullifier and this module will
 * return `verified: true`. That is not a bug here — it is the ceiling
 * of what attestation-only verification can establish.
 *
 * Consequently `BIND_GATE_MODE=attestation` is testnet-only and
 * `index.ts` hard-fails if it is ever combined with
 * `ENVIRONMENT=production`. The mainnet gate re-verifies the Groth16
 * proof against Self's registry on Celo, which a compromised app
 * cannot forge because it cannot write to Celo.
 *
 * ## Implementation notes
 *
 * Uses `node:crypto` exclusively. `@peculiar/x509` was evaluated and
 * rejected: it depends on `tsyringe` (decorator-based DI) and carries a
 * known, open Cloudflare Workers incompatibility — PeculiarVentures/x509
 * issue #116, with fixes still unmerged as of v2.0.0. Cloudflare
 * supports the full `node:crypto` surface under `nodejs_compat`, so
 * `X509Certificate` covers the chain work with no dependency at all.
 */

import { X509Certificate, createHash, createVerify } from 'node:crypto';

/**
 * Google's Confidential Space Root CA, copied verbatim from
 * `self/common/src/utils/attest.ts` (which in turn takes it from
 * Google). Embedded as PEM rather than as a bare fingerprint so a
 * reviewer can decode and inspect it without trusting a hex string.
 *
 * Pinning the root is mandatory but NOT sufficient on its own: an
 * attacker can trivially copy the real root into their own `x5c`.
 * The chain-signature checks in `verifyChain` are what make the pin
 * meaningful.
 */
const GCP_CONFIDENTIAL_SPACE_ROOT_PEM = `-----BEGIN CERTIFICATE-----
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
uyT5CnJulxSC5CT1
-----END CERTIFICATE-----`;

/** Exactly three certificates: leaf, intermediate, root. */
const X5C_LENGTH = 3;

/** Only RS256 is produced by Confidential Space; reject anything else. */
const REQUIRED_JWT_ALG = 'RS256';

/** `image_digest` arrives as `sha256:<64 hex>`. */
const IMAGE_DIGEST_PREFIX = 'sha256:';
const IMAGE_DIGEST_HEX_LENGTH = 64;

/**
 * Tolerance applied to `exp` / `nbf` to absorb clock skew between the
 * enclave and the Cloudflare edge. Deliberately tight — the handshake
 * this token guards is seconds long.
 */
const CLOCK_SKEW_SECONDS = 60;

/** Thrown for every rejection path. `code` is stable for audit logs. */
export class SelfAttestationError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'SelfAttestationError';
  }
}

function reject(code: string, message: string): never {
  throw new SelfAttestationError(code, message);
}

export interface VerifiedSelfAttestation {
  /** Enclave image measurement, lowercase hex, `sha256:` stripped. */
  readonly imageDigest: string;
  /** Client ephemeral ECDH public key, as raw bytes. */
  readonly userPublicKey: Buffer;
  /** Enclave ephemeral ECDH public key, as raw bytes. */
  readonly enclavePublicKey: Buffer;
  /** Value of the `dbgstat` claim. */
  readonly debugStatus: string;
  /** `exp` claim, seconds since epoch, when present. */
  readonly expiresAt: number | null;
  /** `iat` claim, seconds since epoch, when present. */
  readonly issuedAt: number | null;
}

export interface VerifySelfAttestationOptions {
  /**
   * Lowercase-hex image digests this attester accepts. Empty set means
   * "accept any digest that otherwise verifies" and is only permitted
   * when `allowDebugEnclave` is also true (i.e. local dev).
   */
  readonly allowedImageDigests: ReadonlySet<string>;
  /**
   * When true, skips the `dbgstat === 'disabled-since-boot'` check and
   * permits an empty `allowedImageDigests`. Never set in staging or
   * production.
   */
  readonly allowDebugEnclave: boolean;
  /** Injectable clock for tests. Seconds since epoch. */
  readonly nowSeconds?: number;
}

function decodeBase64Url(input: string): Buffer {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

/**
 * Parses the three `x5c` entries. `x5c` is standard base64 (RFC 7515
 * §4.1.6) carrying DER — not base64url, and not PEM.
 */
function parseX5c(x5c: readonly string[]): {
  leaf: X509Certificate;
  intermediate: X509Certificate;
  root: X509Certificate;
} {
  const certs = x5c.map((b64, i) => {
    try {
      return new X509Certificate(Buffer.from(b64, 'base64'));
    } catch (err) {
      reject(
        'ATT_X5C_PARSE_FAILED',
        `x5c[${i}] is not a parseable X.509 certificate: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  });
  return { leaf: certs[0]!, intermediate: certs[1]!, root: certs[2]! };
}

/**
 * Pins the presented root to Google's Confidential Space Root CA by
 * comparing DER bytes. Byte equality rather than fingerprint
 * comparison — there is no reason to hash when we hold both DERs.
 */
function assertPinnedRoot(presentedRoot: X509Certificate): void {
  const pinned = new X509Certificate(GCP_CONFIDENTIAL_SPACE_ROOT_PEM);
  if (!pinned.raw.equals(presentedRoot.raw)) {
    const presentedFingerprint = createHash('sha256')
      .update(presentedRoot.raw)
      .digest('hex');
    reject(
      'ATT_ROOT_NOT_PINNED',
      `x5c root is not the GCP Confidential Space Root CA ` +
        `(presented sha256=${presentedFingerprint}, subject=${presentedRoot.subject})`,
    );
  }
}

/**
 * Verifies leaf <- intermediate <- root signatures and issuer linkage.
 *
 * This is the check that gives the root pin its teeth. Without it an
 * attacker could ship their own leaf plus the genuine Google root and
 * sign the JWT with a key they control.
 */
function verifyChain(
  leaf: X509Certificate,
  intermediate: X509Certificate,
  root: X509Certificate,
): void {
  if (!leaf.checkIssued(intermediate)) {
    reject(
      'ATT_CHAIN_ISSUER_MISMATCH',
      `leaf issuer does not match intermediate subject (leaf.issuer=${leaf.issuer})`,
    );
  }
  if (!intermediate.checkIssued(root)) {
    reject(
      'ATT_CHAIN_ISSUER_MISMATCH',
      `intermediate issuer does not match root subject (intermediate.issuer=${intermediate.issuer})`,
    );
  }
  if (!leaf.verify(intermediate.publicKey)) {
    reject('ATT_CHAIN_SIG_INVALID', 'leaf certificate signature does not verify against intermediate');
  }
  if (!intermediate.verify(root.publicKey)) {
    reject(
      'ATT_CHAIN_SIG_INVALID',
      'intermediate certificate signature does not verify against root',
    );
  }
  if (!root.verify(root.publicKey)) {
    reject('ATT_CHAIN_SIG_INVALID', 'root certificate is not self-signed as expected');
  }
}

/**
 * Validity-window check across all three certificates. Self's own
 * implementation only checks the root, which lets an expired leaf
 * through; we check every cert in the chain.
 */
function assertValidityWindows(
  certs: readonly { label: string; cert: X509Certificate }[],
  nowMs: number,
): void {
  for (const { label, cert } of certs) {
    const notBefore = Date.parse(cert.validFrom);
    const notAfter = Date.parse(cert.validTo);
    if (Number.isNaN(notBefore) || Number.isNaN(notAfter)) {
      reject(
        'ATT_CERT_VALIDITY_UNPARSEABLE',
        `${label} certificate has an unparseable validity window ` +
          `(validFrom=${cert.validFrom}, validTo=${cert.validTo})`,
      );
    }
    if (nowMs < notBefore) {
      reject(
        'ATT_CERT_NOT_YET_VALID',
        `${label} certificate is not valid until ${cert.validFrom}`,
      );
    }
    if (nowMs > notAfter) {
      reject('ATT_CERT_EXPIRED', `${label} certificate expired at ${cert.validTo}`);
    }
  }
}

/** RS256 over `${header}.${payload}` using the leaf's public key. */
function assertJwtSignature(
  signingInput: string,
  signature: Buffer,
  leaf: X509Certificate,
): void {
  const verifier = createVerify('RSA-SHA256');
  verifier.update(signingInput, 'utf8');
  verifier.end();
  if (!verifier.verify(leaf.publicKey, signature)) {
    reject('ATT_JWT_SIG_INVALID', 'attestation JWT signature does not verify against x5c leaf');
  }
}

function extractImageDigest(payload: Record<string, unknown>): string {
  const submods = payload.submods as { container?: { image_digest?: unknown } } | undefined;
  const raw = submods?.container?.image_digest;
  if (typeof raw !== 'string' || raw.length === 0) {
    reject(
      'ATT_IMAGE_DIGEST_MISSING',
      'attestation payload is missing submods.container.image_digest',
    );
  }
  if (!raw.startsWith(IMAGE_DIGEST_PREFIX)) {
    reject(
      'ATT_IMAGE_DIGEST_MALFORMED',
      `image_digest must start with "${IMAGE_DIGEST_PREFIX}", got "${raw.slice(0, 16)}…"`,
    );
  }
  const hex = raw.slice(IMAGE_DIGEST_PREFIX.length).toLowerCase();
  if (hex.length !== IMAGE_DIGEST_HEX_LENGTH || !/^[0-9a-f]+$/.test(hex)) {
    reject(
      'ATT_IMAGE_DIGEST_MALFORMED',
      `image_digest must be ${IMAGE_DIGEST_HEX_LENGTH} hex chars after the prefix, got ${hex.length}`,
    );
  }
  return hex;
}

function extractEatNonce(payload: Record<string, unknown>): {
  userPublicKey: Buffer;
  enclavePublicKey: Buffer;
} {
  const nonce = payload.eat_nonce;
  if (!Array.isArray(nonce) || nonce.length < 2) {
    reject(
      'ATT_EAT_NONCE_MISSING',
      `attestation payload eat_nonce must be an array of at least 2 entries, got ${
        Array.isArray(nonce) ? nonce.length : typeof nonce
      }`,
    );
  }
  const [user, enclave] = nonce;
  if (typeof user !== 'string' || typeof enclave !== 'string') {
    reject('ATT_EAT_NONCE_MALFORMED', 'eat_nonce entries must be base64 strings');
  }
  const userPublicKey = Buffer.from(user, 'base64');
  const enclavePublicKey = Buffer.from(enclave, 'base64');
  if (userPublicKey.length === 0 || enclavePublicKey.length === 0) {
    reject('ATT_EAT_NONCE_MALFORMED', 'eat_nonce entries decoded to empty buffers');
  }
  return { userPublicKey, enclavePublicKey };
}

/**
 * Verify a GCP Confidential Space attestation JWT emitted by a Self
 * proving enclave.
 *
 * Throws `SelfAttestationError` on every rejection path rather than
 * returning a boolean, so a caller cannot accidentally ignore a
 * failure — a mistake that is easy to make against Self's own
 * `validatePKIToken`, which returns `{ verified: false }` and leaves
 * the caller to check it.
 */
export function verifySelfAttestation(
  attestationToken: string,
  options: VerifySelfAttestationOptions,
): VerifiedSelfAttestation {
  if (typeof attestationToken !== 'string' || attestationToken.length === 0) {
    reject('ATT_TOKEN_MISSING', 'attestation token is empty');
  }

  const parts = attestationToken.split('.');
  if (parts.length !== 3) {
    reject(
      'ATT_TOKEN_MALFORMED',
      `attestation token must have 3 dot-separated segments, got ${parts.length}`,
    );
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];

  // ── Header ────────────────────────────────────────────────────────
  let header: { alg?: unknown; x5c?: unknown };
  try {
    header = JSON.parse(decodeBase64Url(encodedHeader).toString('utf8'));
  } catch (err) {
    reject(
      'ATT_HEADER_PARSE_FAILED',
      `attestation header is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (header.alg !== REQUIRED_JWT_ALG) {
    reject(
      'ATT_BAD_ALG',
      `attestation alg must be ${REQUIRED_JWT_ALG}, got ${String(header.alg)}`,
    );
  }
  if (!Array.isArray(header.x5c) || header.x5c.length !== X5C_LENGTH) {
    reject(
      'ATT_BAD_X5C_LENGTH',
      `attestation x5c must contain exactly ${X5C_LENGTH} certificates, got ${
        Array.isArray(header.x5c) ? header.x5c.length : typeof header.x5c
      }`,
    );
  }
  if (!header.x5c.every((entry): entry is string => typeof entry === 'string')) {
    reject('ATT_BAD_X5C_ENTRY', 'every attestation x5c entry must be a base64 string');
  }

  // ── Certificate chain ─────────────────────────────────────────────
  const { leaf, intermediate, root } = parseX5c(header.x5c);
  assertPinnedRoot(root);
  verifyChain(leaf, intermediate, root);

  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  assertValidityWindows(
    [
      { label: 'leaf', cert: leaf },
      { label: 'intermediate', cert: intermediate },
      { label: 'root', cert: root },
    ],
    nowSeconds * 1000,
  );

  // ── JWT signature ─────────────────────────────────────────────────
  assertJwtSignature(
    `${encodedHeader}.${encodedPayload}`,
    decodeBase64Url(encodedSignature),
    leaf,
  );

  // ── Payload ───────────────────────────────────────────────────────
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(decodeBase64Url(encodedPayload).toString('utf8'));
  } catch (err) {
    reject(
      'ATT_PAYLOAD_PARSE_FAILED',
      `attestation payload is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const exp = typeof payload.exp === 'number' ? payload.exp : null;
  const iat = typeof payload.iat === 'number' ? payload.iat : null;
  const nbf = typeof payload.nbf === 'number' ? payload.nbf : null;

  if (exp !== null && nowSeconds > exp + CLOCK_SKEW_SECONDS) {
    reject(
      'ATT_TOKEN_EXPIRED',
      `attestation token expired at ${exp} (now ${nowSeconds}, skew ${CLOCK_SKEW_SECONDS}s)`,
    );
  }
  if (nbf !== null && nowSeconds + CLOCK_SKEW_SECONDS < nbf) {
    reject(
      'ATT_TOKEN_NOT_YET_VALID',
      `attestation token is not valid before ${nbf} (now ${nowSeconds})`,
    );
  }

  const debugStatus = typeof payload.dbgstat === 'string' ? payload.dbgstat : '';
  if (!options.allowDebugEnclave && debugStatus !== 'disabled-since-boot') {
    reject(
      'ATT_DEBUG_ENCLAVE',
      `enclave debug mode must be disabled since boot, got dbgstat="${debugStatus}"`,
    );
  }

  const imageDigest = extractImageDigest(payload);
  const { userPublicKey, enclavePublicKey } = extractEatNonce(payload);

  // ── Image-digest allowlist ────────────────────────────────────────
  // This is the whole point of the exercise: a verified chain only
  // tells us Google signed *something*. The allowlist is what says
  // the code running inside was a Self enclave build we accept.
  if (options.allowedImageDigests.size === 0) {
    if (!options.allowDebugEnclave) {
      reject(
        'ATT_ALLOWLIST_EMPTY',
        'SELF_TEE_IMAGE_DIGESTS is empty; refusing to accept an unmeasured enclave outside dev',
      );
    }
  } else if (!options.allowedImageDigests.has(imageDigest)) {
    reject(
      'ATT_IMAGE_DIGEST_NOT_ALLOWED',
      `enclave image digest ${imageDigest} is not in SELF_TEE_IMAGE_DIGESTS`,
    );
  }

  return {
    imageDigest,
    userPublicKey,
    enclavePublicKey,
    debugStatus,
    expiresAt: exp,
    issuedAt: iat,
  };
}

/**
 * Parse the `SELF_TEE_IMAGE_DIGESTS` var into a normalised set.
 *
 * Accepts comma and/or whitespace separated digests, with or without
 * the `sha256:` prefix, in any case. Rotating Self enclave images
 * means this list legitimately holds more than one entry during a
 * rollout.
 */
export function parseImageDigestAllowlist(raw: string | undefined): Set<string> {
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    return new Set();
  }
  const out = new Set<string>();
  for (const token of raw.split(/[\s,]+/)) {
    if (token.length === 0) continue;
    const hex = (
      token.startsWith(IMAGE_DIGEST_PREFIX) ? token.slice(IMAGE_DIGEST_PREFIX.length) : token
    ).toLowerCase();
    if (hex.length !== IMAGE_DIGEST_HEX_LENGTH || !/^[0-9a-f]+$/.test(hex)) {
      throw new SelfAttestationError(
        'BAD_IMAGE_DIGEST_VAR',
        `SELF_TEE_IMAGE_DIGESTS entry "${token}" is not a ${IMAGE_DIGEST_HEX_LENGTH}-char hex sha256 digest`,
      );
    }
    out.add(hex);
  }
  return out;
}
