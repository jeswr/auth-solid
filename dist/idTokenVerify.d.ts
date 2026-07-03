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
import type { FetchLike } from "./types.js";
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
export declare function verifyIdTokenSignature(params: VerifyIdTokenParams): Promise<Record<string, unknown>>;
//# sourceMappingURL=idTokenVerify.d.ts.map