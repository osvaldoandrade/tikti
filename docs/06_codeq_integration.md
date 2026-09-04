# 06 codeQ Integration

This document specifies the Tikti requirements that enable codeQ producer and worker authentication. The integration is deterministic, auditable, and compatible with existing codeQ flows that rely on token lookup.

## Authentication method independence

SAML-authenticated users who hold membership in a codeQ-enabled tenant can exchange their idToken for a worker token in the same way as password-authenticated users. The `amr: saml` claim in the idToken does not affect the token exchange or the worker authorization path. The token exchange endpoint validates the idToken, verifies tenant membership, and checks scope entitlements without inspecting the authentication method. This means the entire codeQ integration described below works identically for both authentication methods.

## Producer authentication flow

A codeQ producer authenticates using an idToken obtained from Tikti sign-in (password or SAML). codeQ does not verify the idToken signature directly; it calls Tikti's lookup endpoint. The lookup response must include role information so that codeQ can determine whether admin routes are allowed.

The lookup call uses the API key, and the idToken is supplied in the request body. If the response does not include `role`, codeQ cannot grant admin access.

Request:

```http
POST /v1/accounts/lookup?key=API_KEY
Content-Type: application/json

{"idToken":"<idToken>"}
```

Response:

```json
{
  "users": [
    {
      "localId": "uuid",
      "email": "admin@codecompany.com.br",
      "role": "ADMIN",
      "tenantId": "tenant-1",
      "status": "ACTIVE"
    }
  ]
}
```

If the idToken is invalid, Tikti returns 401 and codeQ rejects the request. If the user is suspended, Tikti returns 403 or includes a status that codeQ uses to deny access.

## Worker authentication flow

Workers require RS256 tokens. These tokens are not produced by sign-in. They are produced by a token exchange endpoint that validates a user identity and issues a scoped access token with a specific `aud` and allowed event types.

### Token exchange contract

The token exchange endpoint is used by CLI or automation to obtain a worker token. The caller passes an idToken and specifies the desired `aud`, scope set, and event types. The server validates that the idToken is valid, that the user belongs to the requested tenant, and that requested scopes are a subset of permissions granted to the user and to the client.

Request:

```json
{
  "idToken": "<user-id-token>",
  "audience": "codeq-worker",
  "scopes": ["codeq:claim","codeq:heartbeat","codeq:abandon","codeq:nack","codeq:result","codeq:subscribe"],
  "eventTypes": ["render_video","generate_master"],
  "ttlSeconds": 3600,
  "subject": "worker-1",
  "tenantId": "tenant-1"
}
```

Response:

```json
{
  "accessToken": "<rs256-jwt>",
  "tokenType": "Bearer",
  "expiresIn": 3600
}
```

### Required claims

The worker token includes the following claims: `iss` set to the Tikti issuer base URL (for example, `https://api.storifly.ai`), `aud` set to `codeq-worker`, `sub` set to the worker id, `tid` set to the tenant id, `scope` as a space-delimited string, `eventTypes` as an array of event type strings, and standard temporal claims `iat`, `exp`, `jti`.

### Validation in codeQ

codeQ validates worker tokens by fetching JWKS and selecting the key by `kid`, verifying the RS256 signature, validating that `iss` equals the configured `WORKER_ISSUER`, validating that `aud` equals the configured `WORKER_AUDIENCE`, validating `exp` and `iat` with clock skew tolerance, validating required `scope` per endpoint, and validating event type membership when claiming tasks. Any validation failure results in 401 or 403.

The codeQ configuration values are:

- `WORKER_ISSUER=https://api.storifly.ai`
- `WORKER_AUDIENCE=codeq-worker`
- `WORKER_JWKS_URL=https://api.storifly.ai/.well-known/jwks.json`

## JWKS requirements

codeQ caches JWKS but must refresh on `kid` miss. Tikti publishes JWKS at a stable path and includes all active public keys. Key rotation must be non-disruptive (see token spec).

## Example: issuing a worker token

The following example illustrates a CLI workflow:

```bash
# 1) User logs in
curl -sS -X POST "https://api.storifly.ai/v1/accounts/signInWithPassword?key=API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@codecompany.com.br","password":"mypassword2"}'

# 2) Exchange idToken for worker token
curl -sS -X POST "https://api.storifly.ai/v1/accounts/token/exchange?key=API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"idToken":"<idToken>","audience":"codeq-worker","scopes":["codeq:claim"],"eventTypes":["render_video"],"ttlSeconds":3600,"subject":"worker-1","tenantId":"tenant-1"}'
```

## Failure modes

The integration treats token exchange as an authorization boundary. Failure modes are: invalid idToken returns 401; missing tenant membership returns 403; scope requested outside role permissions returns 403; unknown `aud` returns 400; disallowed event types returns 403. These errors are deterministic and are logged with `tenantId` and `sub`.

## OOB email delivery (out of scope)

OOB email delivery is orchestrated outside of codeQ. Tikti currently generates
and persists the code but has no email or queue dispatcher. A trusted server-side
workflow calls `POST /v1/tenants/{tenantId}/oob/send`, supplies the API key in
`X-API-Key` and a strict RS256 Bearer carrying `code-admin:identity:write` with
signed `tid` equal to the route tenant (or provenance-bound platform-admin
authority), observes `X-Tikti-OOB-Delivery: external-required`, and then calls
the Notifications Service with the returned code. The code-bearing response is
`no-store` compatibility behavior and must never traverse a browser or logs.
