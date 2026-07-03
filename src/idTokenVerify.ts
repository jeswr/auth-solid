// AUTHORED-BY Claude Fable 5
/**
 * Explicit ID-token JWS signature verification — the load-bearing half of the "verified-WebID-only"
 * guarantee.
 *
 * WHY this exists (a real gap, verified against the installed stack): in the Auth.js
 * authorization-code flow, `@auth/core` calls oauth4webapi's `processAuthorizationCodeResponse` +
 * `getValidatedIdTokenClaims`, and NEITHER verifies the ID token's JWS signature. oauth4webapi's
 * `validateJwt` (invoked by `processGenericAccessTokenResponse`) checks only the alg, required
 * claim presence, `iss`, `aud` and time claims — the SIGNATURE is verified solely by the separate
 * `validateApplicationLevelSignature(as, ref, options)` call, which `@auth/core` never makes
 * (verified in @auth/core 0.41 `lib/actions/callback/oauth/callback.js` + oauth4webapi 3.x
 * `build/index.js`). OIDC Core §3.1.3.7 permits skipping signature verification in the code flow
 * because the token arrives over the direct, TLS-authenticated back-channel — but this package
 * routes that back-channel through a consumer-supplied `customFetch` (and `@auth/core` disables
 * oauth4webapi's own https enforcement whenever a `[customFetch]` is present), so we do NOT rely on
 * that assumption: a signature-unverified ID token whose `iss`/`aud`/`nonce` claims happen to match
 * (a mix-up the claim checks don't fully close, a compromised/misbehaving discovery, a swapped
 * token) would otherwise let an attacker forge the WebID. We therefore verify the JWS signature
 * against the OP's published JWKS BEFORE trusting any claim, and read the WebID from the
 * signature-verified payload — fail-closed.
 *
 * All HTTP (discovery + JWKS) goes through the SAME transport-guarded fetch as the rest of the
 * flow (https-only unless `allowInsecure` on loopback). Asymmetric-only: an `HS*` / `none` alg is
 * rejected outright (a symmetric alg against a public JWKS is a classic algorithm-confusion vector).
 */

import { createLocalJWKSet, decodeProtectedHeader, type JWK, jwtVerify } from "jose";
import { assertSecureTransport } from "./dpopFetch.js";
import type { FetchLike } from "./types.js";

/** Strip a single trailing slash so `<issuer>/.well-known/...` is well-formed. */
function trimTrailingSlash(s: string): string {
  return s.endsWith("/") ? s.slice(0, -1) : s;
}

/** Inputs to {@link verifyIdTokenSignature}. */
export interface VerifyIdTokenParams {
  /** The raw ID token (a compact JWS) from the token response. */
  readonly idToken: unknown;
  /** The configured issuer (OP) — the discovery doc's `issuer` MUST equal this, and so must `iss`. */
  readonly issuer: string;
  /** The client id — the ID token's `aud` MUST include it. */
  readonly clientId: string;
  /** The transport-guarded fetch used for discovery + JWKS (the provider's DPoP customFetch). */
  readonly fetch: FetchLike;
  /** Permit http: on loopback for discovery/JWKS (dev OP). Default false (https-only). */
  readonly allowInsecure: boolean;
}

/**
 * Verify the ID token's JWS signature against the OP's JWKS and its `iss`/`aud` claims, returning
 * the SIGNATURE-VERIFIED claim set. Throws (fail-closed) on any failure: a missing/malformed token,
 * a symmetric/`none` alg, an unreachable/mismatched discovery doc, a JWKS that doesn't contain the
 * signing key, or a bad signature.
 *
 * The returned payload is the ONLY claim set a caller should trust for identity (the WebID).
 */
export async function verifyIdTokenSignature(
  params: VerifyIdTokenParams,
): Promise<Record<string, unknown>> {
  const { idToken, issuer, clientId, fetch, allowInsecure } = params;

  if (typeof idToken !== "string" || idToken.length === 0) {
    throw new Error(
      "auth-solid: the token response carried no `id_token`; refusing to establish a session " +
        "without a signature-verifiable ID token (fail-closed).",
    );
  }

  // Reject a symmetric / `none` alg up front — a public JWKS must never be used with an HMAC alg
  // (algorithm-confusion), and `none` is unsigned. Solid-OIDC ID tokens are asymmetric.
  let alg: string;
  try {
    alg = decodeProtectedHeader(idToken).alg ?? "";
  } catch {
    throw new Error("auth-solid: the ID token header is not a valid JWS (fail-closed).");
  }
  if (alg === "" || alg.toUpperCase().startsWith("HS") || alg.toLowerCase() === "none") {
    throw new Error(
      `auth-solid: the ID token uses a non-asymmetric signature alg "${alg}"; only asymmetric ` +
        "algorithms are accepted (fail-closed).",
    );
  }

  const base = trimTrailingSlash(issuer);
  const discoveryUrl = `${base}/.well-known/openid-configuration`;
  // Transport guard on discovery + JWKS (the fetch itself is the same guarded customFetch, but
  // assert here too so a bad URL fails with a clear message before any network call).
  assertSecureTransport(
    discoveryUrl,
    allowInsecure,
    (msg) => new Error(`auth-solid ID-token verify: discovery ${msg}`),
  );

  const discoveryRes = await fetch(discoveryUrl);
  if (!discoveryRes.ok) {
    throw new Error(
      `auth-solid: could not fetch the OP discovery document (${discoveryRes.status}) to verify ` +
        "the ID-token signature (fail-closed).",
    );
  }
  const discovery = (await discoveryRes.json()) as { issuer?: unknown; jwks_uri?: unknown };
  // The discovery doc's issuer identity MUST match the configured issuer (RFC 8414 §3.3) — a
  // mismatch means we are not talking to the OP we think we are.
  if (discovery.issuer !== issuer) {
    throw new Error(
      "auth-solid: the OP discovery document `issuer` does not match the configured issuer " +
        "(fail-closed).",
    );
  }
  const jwksUri = discovery.jwks_uri;
  if (typeof jwksUri !== "string" || jwksUri.length === 0) {
    throw new Error("auth-solid: the OP discovery document has no `jwks_uri` (fail-closed).");
  }
  assertSecureTransport(
    jwksUri,
    allowInsecure,
    (msg) => new Error(`auth-solid ID-token verify: jwks_uri ${msg}`),
  );

  const jwksRes = await fetch(jwksUri);
  if (!jwksRes.ok) {
    throw new Error(
      `auth-solid: could not fetch the OP JWKS (${jwksRes.status}) to verify the ID-token ` +
        "signature (fail-closed).",
    );
  }
  const jwks = (await jwksRes.json()) as { keys?: unknown };
  if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    throw new Error("auth-solid: the OP JWKS contains no keys (fail-closed).");
  }

  const keySet = createLocalJWKSet({ keys: jwks.keys as JWK[] });
  try {
    const { payload } = await jwtVerify(idToken, keySet, {
      issuer,
      audience: clientId,
    });
    return payload as Record<string, unknown>;
  } catch (err) {
    // Do NOT include the token in the message (no secret leak). Surface only that verification
    // failed — the caller fails closed.
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`auth-solid: ID-token signature verification failed (${reason}) (fail-closed).`);
  }
}
