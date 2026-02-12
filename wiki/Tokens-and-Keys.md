> Canonical source: [`docs/03_tokens_and_keys.md`](https://github.com/osvaldoandrade/tikti/blob/main/docs/03_tokens_and_keys.md)
> Synced on: 2026-02-12

# Tokens and Keys

This document defines the token taxonomy, claim semantics, signing algorithms, JWKS publishing, and verification rules. It is written to support interoperable validation by external resource servers such as codeQ. The token model is intentionally explicit; a token is valid only when all required claims are present and validated against configuration and policy.

## Token classes

Tikti issues three classes of JWTs. Each class exists for a different purpose and has distinct validation rules. Mixing these classes is not allowed.

### Identity token (idToken)

An idToken represents authenticated user identity. It is issued during sign‑in and is suitable for lookup and for exchanging into access tokens. It is not sufficient for resource authorization unless the resource explicitly accepts idTokens.

Required claims:

- `sub`: stable user id
- `email`: user email
- `role`: global role (ADMIN, COMPANY_ADMIN, COMPANY_EMPLOYEE)
- `tid`: tenant id (required when multi‑tenant is enabled)
- `iss`: issuer string
- `aud`: client id (optional in legacy mode, required in target mode)
- `iat`: issued at (epoch seconds)
- `exp`: expiration (epoch seconds)

Algorithm:

- Legacy: HS256 signed with `jwtSecret`
- Target: RS256 optional if configured

Lifetime: 3600 seconds, unless configured otherwise.

### Access token

An access token authorizes a client to call a resource server. The resource server validates `aud`, `iss`, `exp`, `scope`, and `tid`. Access tokens are obtained via token exchange; they are not produced by sign‑in.

Required claims:

- `sub`: user id or service id
- `tid`: tenant id
- `aud`: resource server identifier
- `scope`: space‑delimited permissions
- `iss`, `iat`, `exp`, `jti`

Algorithm: RS256 only.

Lifetime: 900–3600 seconds, configured per client.

### Worker token

A worker token is a specialized access token for codeQ workers. It must be RS256 and must include an `eventTypes` claim, which defines the set of event types the worker may claim.

Required claims:

- `sub`: worker id
- `tid`: tenant id
- `aud`: `codeq-worker`
- `scope`: `codeq:claim codeq:heartbeat codeq:abandon codeq:nack codeq:result codeq:subscribe`
- `eventTypes`: array of event types
- `iss`, `iat`, `exp`, `jti`

Lifetime: 900–3600 seconds. Shorter lifetimes are recommended for workers.

## Issuer (`iss`) semantics

Issuer is a stable identifier of the Tikti deployment environment and is used to prevent token replay across environments. The issuer must match the public base URL of the service and must not include path segments that are unstable.

Examples:

- `https://api.storifly.ai`
- `https://api.itransform.cc`

If a realm‑specific issuer is desired, the issuer can include `/realms/{tenantSlug}` but only if all resource servers are configured to trust that issuer. The default mode is a single issuer per environment with tenant encoded in `tid`.

## Audience (`aud`) semantics

Audience identifies the intended resource server. It is required for access and worker tokens. It should be optional only for legacy idTokens during transition.

Examples:

- `codeq-worker`
- `codeq-producer`
- `codeflow-api`

Resource servers must reject tokens whose `aud` does not match their configured audience set.

## Scope semantics

Scope is a space‑delimited string of permission identifiers. Scopes are not hierarchical; each scope is an atomic permission.

Example:

```
codeq:claim codeq:result codeq:subscribe
```

Authorization algorithms treat scope as a set. Membership roles map to scopes via role definitions. Scope evaluation must be exact string match with no wildcard expansion unless explicitly implemented.

## JWKS and key distribution

Access and worker tokens are validated via RS256 and JWKS. Tikti must publish public keys in JWKS format at a stable URL.

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

Headers:

- `Cache-Control: public, max-age=300`

JWKS must include all currently valid public keys. Tokens must include a `kid` so the verifier can select the correct key.

## Key rotation

Key rotation must be non‑disruptive. The rotation algorithm is:

1. Generate a new RSA keypair with a new `kid`.
2. Add the new public key to JWKS and deploy.
3. Begin signing new tokens with the new key.
4. Keep the old key in JWKS for at least `max(token_lifetime) + clock_skew` seconds.
5. Remove the old key after the grace period expires.

This guarantees that all issued tokens remain verifiable until they expire. The old private key can be deleted after step 4 if no tokens are signed with it.

## Token validation algorithm

The token validation algorithm is uniform across resource servers. The algorithm below applies to RS256 tokens.

Pseudo‑code:

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

Complexity:

- Parsing: O(1)
- JWKS lookup: O(1) after caching
- Signature verification: O(1)
- Scope subset check: O(s + p), where s is required scopes and p is token scope count

For HS256 idTokens, JWKS is not used; the algorithm validates the HMAC signature using `jwtSecret`, then applies the same time and issuer checks.

## Token exchange constraints

Token exchange must validate the incoming idToken. The `iss` and `aud` checks apply to idTokens as well. The exchange must verify tenant membership before issuing an access token with `tid`. It must also restrict scopes to those permitted by the user’s roles and by the client configuration.

The exchange algorithm complexity is dominated by role expansion and scope intersection, both O(r + p). With bounded role counts, the overall cost is effectively O(1).

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
