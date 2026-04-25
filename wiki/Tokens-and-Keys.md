# Tokens and Keys

This document defines the token taxonomy, claim semantics, signing algorithms, JWKS publishing, key management, and verification rules. It serves as a contract for resource servers that validate Tikti-issued tokens. A token is valid only when every required claim is present and passes validation against the deployment configuration and tenant policy.

## Token classes

Tikti issues three classes of JWTs. Each class has a distinct purpose and distinct validation rules. Mixing classes across validation paths is prohibited.

### Identity token (idToken)

An idToken represents authenticated user identity. Tikti issues an idToken at the conclusion of every sign-in path: password, out-of-band email, and SAML 2.0. The sign-in method does not alter the token structure. Password sign-in, OOB sign-in, and SAML sign-in all produce an HS256 idToken with identical claim layout. The `amr` claim records which method was used (`pwd`, `oob`, or `saml`), allowing downstream consumers to make policy decisions based on authentication method without requiring separate token handling.

An idToken is suitable for identity lookup and for exchanging into an access token. It is not sufficient for resource authorization unless the resource explicitly accepts idTokens.

| Claim | Description |
|-------|-------------|
| `sub` | Stable user identifier |
| `email` | User email |
| `role` | Global role: `ADMIN`, `COMPANY_ADMIN`, or `COMPANY_EMPLOYEE` |
| `tid` | Tenant identifier (required when multi-tenant is enabled) |
| `amr` | Authentication method: `pwd`, `oob`, or `saml` |
| `iss` | Issuer string |
| `aud` | Client identifier (optional in legacy mode, required in target mode) |
| `iat` | Issued-at timestamp (epoch seconds) |
| `exp` | Expiration timestamp (epoch seconds) |

Algorithm: HS256 signed with `jwtSecret`. RS256 is available as a target-mode option if configured.

Lifetime: 3600 seconds by default; configurable per deployment.

### Access token

An access token authorizes a client to call a resource server. Resource servers validate `aud`, `iss`, `exp`, `scope`, and `tid`. Access tokens are obtained through token exchange; they are never produced directly by sign-in. The token exchange path is identical regardless of whether the input idToken was produced by password, OOB, or SAML authentication. The exchange logic verifies the HS256 signature on the idToken, checks tenant membership, expands roles into scopes, and signs the resulting access token with RS256 using the JWKS keypair.

| Claim | Description |
|-------|-------------|
| `sub` | User identifier or service identifier |
| `tid` | Tenant identifier |
| `aud` | Resource server identifier |
| `scope` | Space-delimited permission set |
| `iss` | Issuer string |
| `iat` | Issued-at timestamp (epoch seconds) |
| `exp` | Expiration timestamp (epoch seconds) |
| `jti` | Unique token identifier |

Algorithm: RS256.

Lifetime: 900 to 3600 seconds, configured per client.

### Worker token

A worker token is a specialized access token for codeQ workers. It uses RS256 and includes an `eventTypes` claim that defines the set of event types the worker may claim.

| Claim | Description |
|-------|-------------|
| `sub` | Worker identifier |
| `tid` | Tenant identifier |
| `aud` | `codeq-worker` |
| `scope` | `codeq:claim codeq:heartbeat codeq:abandon codeq:nack codeq:result codeq:subscribe` |
| `eventTypes` | Array of event types |
| `iss` | Issuer string |
| `iat` | Issued-at timestamp (epoch seconds) |
| `exp` | Expiration timestamp (epoch seconds) |
| `jti` | Unique token identifier |

Lifetime: 900 to 3600 seconds. Shorter lifetimes reduce the blast radius of a compromised worker credential.

## Issuer (`iss`) semantics

The issuer is a stable identifier of the Tikti deployment environment. It prevents token replay across environments. The issuer matches the public base URL of the service and does not include path segments that change between deployments.

Examples: `https://api.storifly.ai`, `https://api.itransform.cc`.

A realm-specific issuer can include `/realms/{tenantSlug}`, but only when all resource servers are configured to trust that issuer. The default mode uses a single issuer per environment with the tenant encoded in `tid`.

## Audience (`aud`) semantics

The audience identifies the intended resource server. It is required for access and worker tokens. It is optional for legacy idTokens during the transition period.

Examples: `codeq-worker`, `codeq-producer`, `codeflow-api`.

Resource servers reject tokens whose `aud` does not match their configured audience set.

## Scope semantics

Scope is a space-delimited string of permission identifiers. Scopes are not hierarchical; each scope is an atomic permission. Authorization treats scope as a set. Role definitions map membership roles to scopes. Scope evaluation uses exact string matching with no wildcard expansion unless explicitly implemented.

Example:

```
codeq:claim codeq:result codeq:subscribe
```

## Key inventory

Tikti manages two independent RSA keypairs that serve distinct purposes. Conflating them would break both the SAML protocol and the JWT verification contract.

**JWKS keypair (RS256, access tokens).** This keypair signs access tokens and worker tokens. Resource servers fetch the public key from `/.well-known/jwks.json` and verify RS256 signatures offline. The `kid` header in each token selects the correct public key. This keypair never participates in SAML protocol messages.

**SAML SP keypair (RSA-SHA256, SAML protocol).** This keypair signs SAML AuthnRequest XML documents and decrypts encrypted assertions received from external IdPs. Tikti uses a singleton RSA keypair for all tenants in v1; per-tenant SP keys are planned for v2. The SP keypair never signs JWTs. It is loaded from disk at process start (default path `/etc/tikti/saml/sp.key` and `sp.crt`) and held in memory. When `saml.enabled` is `false`, the SP keypair is not loaded.

The two keypairs have separate rotation lifecycles, separate storage locations, and separate trust relationships. The JWKS public key is distributed via HTTPS to resource servers. The SP public certificate is distributed via SAML metadata XML to external IdPs.

## JWKS and key distribution

Access and worker tokens are validated via RS256 and JWKS. Tikti publishes public keys in JWKS format at a stable URL.

Endpoint:

```
GET /.well-known/jwks.json
```

Response:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "tikti-2026-01",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

Headers: `Cache-Control: public, max-age=300`.

The JWKS response includes all public keys that are currently valid. Every token includes a `kid` header so the verifier can select the correct key.

## Key rotation

Both the JWKS keypair and the SAML SP keypair follow the same rotation principle: overlapping validity windows prevent request failures during the transition.

### JWKS key rotation

The rotation sequence for the JWKS RS256 keypair proceeds as follows:

1. Generate a new RSA keypair with a new `kid`.
2. Add the new public key to JWKS and deploy.
3. Begin signing new tokens with the new key.
4. Keep the old key in JWKS for at least `max(token_lifetime) + clock_skew` seconds.
5. Remove the old key after the grace period expires.

This guarantees that every issued token remains verifiable until it expires. The old private key can be deleted after step 4 when no tokens signed with it remain in circulation.

### SAML SP key rotation

The SAML SP keypair rotation uses a two-phase process managed by the `saml keys rotate` CLI command. External IdPs cache the SP metadata containing the SP certificate, so the old certificate must remain valid long enough for every IdP to refresh its cache.

1. `tikti saml sp rotate --prepare` generates a new RSA keypair and publishes both the old and new certificates in SP metadata. Tikti continues signing AuthnRequests with the old key. IdPs see both certificates and accept signatures from either.
2. After a grace period (72 hours by default, allowing IdP metadata refresh), `tikti saml sp rotate --commit` switches signing to the new key and removes the old certificate from metadata.

During the overlap window, Tikti accepts encrypted assertions encrypted to either key. After commit, the old private key is deleted from disk. The overlap window avoids AuthnRequest signature failures that would occur if the SP certificate changed before an IdP refreshed its cached metadata.

## Token validation algorithm

The token validation algorithm is uniform across resource servers. The following pseudocode applies to RS256 access and worker tokens.

```text
function validate(token, expectedIss, expectedAud, requiredScopes):
  header, payload, sig = parse_jwt(token)
  if header.alg != 'RS256': reject
  key = jwks.get(header.kid)
  if key == null: reject
  if !verify_rs256(key, header.payload, sig): reject
  if payload.iss != expectedIss: reject
  if expectedAud not in payload.aud: reject
  now = current_time()
  if payload.iat > now + skew: reject
  if payload.exp < now - skew: reject
  if requiredScopes not subset of payload.scope: reject
  return payload
```

| Step | Complexity |
|------|------------|
| Parsing | O(1) |
| JWKS lookup | O(1) after caching |
| Signature verification | O(1) |
| Scope subset check | O(s + p), where s = required scopes, p = token scope count |

For HS256 idTokens, JWKS is not used. The algorithm validates the HMAC signature using `jwtSecret`, then applies the same time and issuer checks.

## Token exchange constraints

Token exchange validates the incoming idToken regardless of which authentication method produced it. The `iss` and `aud` checks apply to idTokens from all paths. The exchange verifies tenant membership before issuing an access token with `tid`. It restricts scopes to those permitted by the user's roles and by the client configuration. The `amr` claim from the idToken does not influence scope expansion; all authentication methods receive equivalent authorization.

The exchange algorithm complexity is dominated by role expansion and scope intersection, both O(r + p). With bounded role counts, the cost is O(1).

## Example: worker token payload

```json
{
  "iss": "https://api.storifly.ai",
  "aud": "codeq-worker",
  "sub": "worker-1",
  "tid": "tenant-1",
  "scope": "codeq:claim codeq:heartbeat codeq:abandon codeq:nack codeq:result codeq:subscribe",
  "eventTypes": ["render_video","generate_master"],
  "iat": 1769532214,
  "exp": 1769535814,
  "jti": "uuid"
}
```
