# 06 codeQ Integration

This document specifies the Tikti requirements that enable codeQ producer and worker authentication. The goal is to make the integration deterministic, auditable, and secure, while preserving compatibility with existing codeQ flows that rely on token lookup.

## Producer authentication flow

A codeQ producer authenticates using an idToken obtained from Tikti sign‑in. codeQ does not verify the signature directly; instead, it calls Tikti’s lookup endpoint. This flow requires the lookup response to include role information so that codeQ can decide whether admin routes are allowed.

The lookup call uses the API key, and the idToken is supplied in the request body. The contract is strict: if the response does not include `role`, codeQ cannot grant admin access.

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

If the idToken is invalid, Tikti must return 401 and codeQ must reject the request. If the user is suspended, Tikti should return a 403 or include status that codeQ uses to deny access.

## Worker authentication flow

Workers require RS256 tokens. These are not produced by sign‑in. They are produced by a token exchange endpoint that validates a user identity and issues a scoped access token with a specific audience and allowed event types.

### Token exchange contract

The token exchange endpoint is used by CLI or automation to obtain a worker token. The caller passes an idToken and specifies the desired audience, scope set, and event types. The server must validate that the idToken is valid, that the user belongs to the requested tenant, and that requested scopes are a subset of permissions granted to the user and to the client.

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

The worker token must include:

- `iss`: Tikti issuer base URL (example: `https://api.storifly.ai`)
- `aud`: `codeq-worker`
- `sub`: worker id
- `tid`: tenant id
- `scope`: space‑delimited scopes
- `eventTypes`: array of event type strings
- `iat`, `exp`, `jti`

### Validation in codeQ

codeQ validates worker tokens by performing the following checks:

1. Fetch JWKS and select key by `kid`.
2. Verify RS256 signature.
3. Validate `iss` equals configured `WORKER_ISSUER`.
4. Validate `aud` equals configured `WORKER_AUDIENCE`.
5. Validate `exp` and `iat` with clock skew.
6. Validate required scope per endpoint.
7. Validate event type membership when claiming tasks.

Any failure results in 401 or 403. The codeQ configuration values are:

- `WORKER_ISSUER=https://api.storifly.ai`
- `WORKER_AUDIENCE=codeq-worker`
- `WORKER_JWKS_URL=https://api.storifly.ai/.well-known/jwks.json`

## JWKS requirements

codeQ caches JWKS but must be able to refresh on `kid` miss. Tikti must publish JWKS at a stable path and must include all active public keys. Key rotation must be non‑disruptive (see token spec).

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

The integration must treat token exchange as an authorization boundary. Failure modes are explicit:

- Invalid idToken: 401.
- Tenant membership missing: 403.
- Scope requested outside role permissions: 403.
- Unknown audience: 400.
- Event types not allowed: 403.

These errors must be deterministic and must be logged with tenantId and subject.

## OOB email delivery (out of scope)

OOB email delivery is orchestrated outside of codeQ. The recommended approach is to use a workflow engine (for example, Cadence) to:

1) call Tikti to generate and persist an OOB code (`POST /v1/tenants/{tenantId}/oob/send?key=API_KEY`), and then
2) call the Notifications Service to send the email containing the code.

This keeps Tikti focused on identity/token policy and keeps email delivery concerns outside the identity boundary.
