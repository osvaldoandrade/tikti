# 04 API Specification

This document specifies the HTTP contract for Tikti. It describes endpoint behavior, payloads, validation rules, and error semantics. All endpoints accept and return JSON with UTF‑8 encoding. The base URL is environment‑specific but the path structure is stable. In this document, the base URL is `https://api.storifly.ai`.

## Conventions

All request bodies are JSON. All responses are JSON. Time values are RFC3339 strings unless explicitly stated as epoch seconds.

### Error shape

Errors are returned using a consistent object shape:

```json
{
  "error": "human readable message",
  "code": "MACHINE_CODE",
  "details": {"field": "reason"}
}
```

The `error` field is mandatory to preserve compatibility with existing clients that only parse this string. `code` and `details` are additive.

### Authentication

Protected endpoints require an API key passed as a query parameter: `?key=API_KEY`. This is a compatibility requirement. API keys must be stored hashed and compared securely by the server.

Admin endpoints require the caller to be authenticated with a token that includes `role=ADMIN` or a role that is equivalent by policy. This is enforced using the token claims in the `Authorization` header or in the `idToken` payload where specified.

## Identity endpoints

### POST /v1/accounts/signIn

Authenticates a user with email and password. This is a public endpoint and must not require an API key. The response is an identity token.

Request:

```json
{
  "email": "user@company.com",
  "password": "secret",
  "returnSecureToken": true
}
```

Response 200:

```json
{
  "idToken": "<jwt>",
  "email": "user@company.com",
  "localId": "uuid",
  "expiresIn": 3600
}
```

Error cases:

- 401 if credentials are invalid.
- 400 if request is malformed.

### POST /v1/accounts/signInWithPassword?key=API_KEY

Identical to `/signIn`, but requires an API key. This endpoint exists to mimic Firebase APIs and to enforce API key usage for server‑to‑server usage.

### POST /v1/accounts/signUp

Creates a new user. The caller must include an admin token in the `Authorization` header. The token must be validated with issuer and expiration checks. For compatibility, the token is currently a raw JWT string rather than `Bearer` format; the service must accept both.

Request:

```json
{
  "email": "new@company.com",
  "password": "secret",
  "role": "COMPANY_EMPLOYEE"
}
```

Response 200:

```json
{
  "localId": "uuid",
  "email": "new@company.com",
  "createdAt": "2026-01-28T12:00:00Z"
}
```

Constraints:

- `email` must be globally unique.
- `role` defaults to `COMPANY_EMPLOYEE`.

### POST /v1/accounts/lookup?key=API_KEY

Resolves an idToken to user identity metadata. This endpoint is required for codeQ producer validation. The token is provided in the request body.

Request:

```json
{
  "idToken": "<jwt>"
}
```

Response 200 (target shape):

```json
{
  "users": [
    {
      "localId": "uuid",
      "email": "user@company.com",
      "role": "ADMIN",
      "tenantId": "tenant-1",
      "status": "ACTIVE"
    }
  ]
}
```

The response must always include `role` when available. If multi‑tenant is enabled, `tenantId` must be present. This allows downstream services to enforce admin operations and tenant scoping without additional calls.

### POST /v1/accounts/update?key=API_KEY

Updates email and/or password for the authenticated user. The user is authenticated by the idToken supplied in the payload.

Request:

```json
{
  "idToken": "<jwt>",
  "email": "new@company.com",
  "password": "new-secret"
}
```

Response 200:

```json
{"localId":"uuid","email":"new@company.com"}
```

### POST /v1/accounts/delete?key=API_KEY

Deletes the authenticated user. The idToken provided in the request identifies the user.

Request:

```json
{"idToken":"<jwt>"}
```

Response 200: empty JSON object.

### POST /v1/accounts/sendOobCode?key=API_KEY

Generates an out‑of‑band code for password reset, email verification, or email sign‑in.

`requestType` binds the generated code to a specific flow. The server must persist this type alongside the code and must reject codes used with the wrong consumption endpoint.

Supported `requestType` values:

- `PASSWORD_RESET`: consumed by `/v1/accounts/resetPassword`.
- `EMAIL_SIGNIN`: consumed by `/v1/accounts/signInWithOobCode`.

Request:

```json
{
  "requestType": "PASSWORD_RESET",
  "email": "user@company.com"
}
```

Response 200:

```json
{
  "kind": "identitytoolkit#GetOobConfirmationCodeResponse",
  "email": "user@company.com",
  "oobCode": "uuid"
}
```

The code must be valid for 15 minutes by default.
The code must be single‑use: after a successful consumption, it must be deleted and subsequent uses must fail.

For `EMAIL_SIGNIN`, the server should return 200 regardless of whether the email exists or is eligible (anti‑enumeration). Clients must not treat a successful response as proof that an account exists.

### POST /v1/accounts/signInWithOobCode

Authenticates a user using an out‑of‑band code previously generated by `/v1/accounts/sendOobCode` with `requestType=EMAIL_SIGNIN`. This enables passwordless sign‑in flows (for example, users arriving from a landing page and confirming a token sent to their email inbox).

Request:

```json
{
  "email": "user@company.com",
  "oobCode": "uuid",
  "returnSecureToken": true
}
```

Response 200:

```json
{
  "idToken": "<jwt>",
  "email": "user@company.com",
  "localId": "uuid",
  "expiresIn": 3600
}
```

Error cases:

- 401 if the OOB code is invalid, expired, already consumed, bound to a different email, or has a different `requestType`.
- 400 if request is malformed.

### POST /v1/tenants/{tenantId}/oob/send?key=API_KEY

Generates and persists an OOB code for the given tenant and returns the `oobCode` so that an external orchestrator can deliver it (for example, a Cadence workflow that calls Tikti and then calls the Notifications Service to send the email).

For `EMAIL_SIGNIN`, the server may create a user record when the email does not yet exist, and should scope the user to the tenant provided in the path.

Request:

```json
{
  "requestType": "EMAIL_SIGNIN",
  "email": "user@company.com"
}
```

Response 200:

```json
{
  "kind": "tikti#SendOobResponse",
  "email": "user@company.com",
  "requestType": "EMAIL_SIGNIN",
  "expiresIn": 900,
  "oobCode": "uuid"
}
```

Error cases:

- 400 if tenantId or request is invalid.
- 403 if user is suspended or not allowed for the tenant.
- 404 for `PASSWORD_RESET` when the user does not exist.
- 500 if the server cannot persist the OOB code.

### POST /v1/accounts/resetPassword?key=API_KEY

Resets password using an out‑of‑band code.
The OOB code must have been issued with `requestType=PASSWORD_RESET`.

Request:

```json
{
  "oobCode": "uuid",
  "newPassword": "new-secret"
}
```

Response 200: empty JSON object.

## Administrative user lifecycle

Administrative operations on user status and token revocation are required for operational safety. These endpoints are new and are intended for admin tokens only. They are distinct from `delete` because they must apply to arbitrary users rather than the caller.

### POST /v1/accounts/status?key=API_KEY

Sets the status of a user. Valid statuses are `ACTIVE`, `INACTIVE`, and `SUSPENDED`. A suspended user cannot sign in and cannot exchange tokens.

Request:

```json
{
  "email": "user@company.com",
  "status": "SUSPENDED"
}
```

Response 200:

```json
{
  "localId": "uuid",
  "email": "user@company.com",
  "status": "SUSPENDED"
}
```

The server must log the actor, tenant context (if applicable), and the status transition.

### POST /v1/accounts/revoke?key=API_KEY

Revokes tokens for a user by incrementing the token version. Tokens carry a `ver` claim and are rejected if `ver` does not match the current version stored for the user (and optionally for membership).

Request:

```json
{
  "email": "user@company.com",
  "scope": "global"
}
```

Response 200:

```json
{
  "localId": "uuid",
  "email": "user@company.com",
  "tokenVersion": 4,
  "revokedAt": "2026-01-28T12:00:00Z"
}
```

If `scope` is `tenant`, the request must include `tenantId` and only tenant‑scoped tokens are invalidated. This operation is O(1) because it updates a single record in storage.

## Token exchange

### POST /v1/accounts/token/exchange?key=API_KEY

Exchanges an identity token for an access token. This endpoint is the mechanism by which codeQ workers obtain RS256 tokens with scopes and event types.

Request:

```json
{
  "idToken": "<user-id-token>",
  "audience": "codeq-worker",
  "scopes": ["codeq:claim","codeq:heartbeat","codeq:result"],
  "eventTypes": ["render_video"],
  "ttlSeconds": 3600,
  "subject": "worker-1",
  "tenantId": "tenant-1"
}
```

Semantics:

- `idToken` is verified using HS256 or RS256 depending on configuration.
- `tenantId` must refer to a membership belonging to the token subject.
- `audience` must be a registered client identifier.
- `scopes` must be a subset of the union of role permissions and client allowed scopes.
- `eventTypes` must be validated against tenant or client policy.

Response 200:

```json
{
  "accessToken": "<rs256-jwt>",
  "tokenType": "Bearer",
  "expiresIn": 3600
}
```

Error cases:

- 401 if idToken is invalid.
- 403 if scopes exceed permissions or membership is missing.
- 400 if audience is unknown or request is malformed.

## JWKS

### GET /.well-known/jwks.json

Returns the public keys for RS256 token verification.

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

The JWKS response must include all active public keys and must be cacheable.

## Tenant management (admin)

Tenant management endpoints are required for multi‑tenant support. These endpoints are not implemented in the current baseline and are defined for the target system.

### POST /v1/tenants

Creates a tenant. Requires ADMIN token.

Request:

```json
{
  "name": "Code Company",
  "slug": "codecompany"
}
```

Response:

```json
{
  "id": "tenant-1",
  "name": "Code Company",
  "slug": "codecompany",
  "status": "ACTIVE",
  "createdAt": "2026-01-28T12:00:00Z"
}
```

### GET /v1/tenants/id/{tenantId}

Returns tenant metadata. Requires ADMIN or TENANT_ADMIN for the tenant.

## Membership management (admin)

### POST /v1/tenants/{tenantId}/users

Creates a membership for a user within a tenant. If the user does not exist, the endpoint may create the user with a generated password or return a 400, based on policy.

Request:

```json
{
  "email": "user@company.com",
  "roles": ["TENANT_USER"]
}
```

### POST /v1/tenants/{tenantId}/users/remove

Removes a membership for a user within a tenant. The user record remains, but the tenant association is deleted. This endpoint is used for access revocation without deleting the account.

Request:

```json
{
  "email": "user@company.com"
}
```

Response:

```json
{
  "tenantId": "tenant-1",
  "userId": "user-123",
  "email": "user@company.com",
  "removedAt": "2026-01-28T12:01:00Z"
}
```

## Client management (admin)

### POST /v1/tenants/{tenantId}/clients

Creates a client for token exchange.

Request:

```json
{
  "clientId": "codeq-worker",
  "type": "SERVICE",
  "allowedGrantTypes": ["token_exchange"],
  "defaultScopes": ["codeq:claim","codeq:result"]
}
```

Response includes a generated client secret. The secret must be returned only once.

## Role management (admin)

### POST /v1/tenants/{tenantId}/roles

Creates a role and its permissions.

Request:

```json
{
  "name": "CODEQ_ADMIN",
  "permissions": ["codeq:admin","codeq:claim","codeq:result"]
}
```

## Notes on backward compatibility

All new endpoints are additive. Existing endpoints must remain unchanged in path and payload shape. The server must accept legacy tokens and continue to support lookup responses that omit newer fields, but it should include them when available.
