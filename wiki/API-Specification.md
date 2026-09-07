# API Specification

This document specifies the HTTP contract for Tikti. Every endpoint accepts and returns JSON with UTF-8 encoding unless stated otherwise. The base URL varies by environment; this document uses `https://api.storifly.ai`. Path structure does not change between environments.

## Conventions

Request and response bodies use JSON. Time values use RFC 3339 strings unless stated as epoch seconds.

### Error shape

Every error response uses a single object shape:

```json
{
  "error": "human readable message",
  "code": "MACHINE_CODE",
  "details": {"field": "reason"}
}
```

The `error` field is mandatory. Clients that predate the `code` and `details` fields parse only `error`, so the server must always populate it. The `code` and `details` fields are additive; their absence must not break existing parsers.

### Authentication

Protected endpoints accept the service API key only in `X-API-Key` and compare it in constant time. A `key` query parameter is rejected even when the correct header is present, preventing credentials from entering URLs, browser history, proxy telemetry, and access logs.

Administrative endpoints read a strict RS256 access token from `Authorization: Bearer ...` and validate the configured issuer and Code Admin audience. Platform authority requires `code-admin:tenants:admin`, persisted `ADMIN` role, and `tikti_platform_privilege=platform-admin`; tenant-local authority requires an identity read/write scope and exact signed `tid` according to the operation. Raw tokens, HS256 identity tokens, role-only claims, and scope-only platform claims are rejected.

## Identity endpoints

### POST /v1/accounts/signIn

Authenticates a user with email and password. This endpoint is public and does not require an API key.

Request:

```json
{
  "email": "user@company.com",
  "password": "secret",
  "returnSecureToken": true
}
```

Response 201:

```json
{
  "idToken": "<jwt>",
  "email": "user@company.com",
  "localId": "uuid",
  "expiresIn": 3600
}
```

Error cases:

| Status | Condition |
|--------|-----------|
| 401 | Credentials are invalid. |
| 400 | Request body is malformed. |

### POST /v1/accounts/signInWithPassword

Behaves identically to `/signIn` but requires an API key. This endpoint exists to match the Firebase API surface and to enforce API key usage in server-to-server calls.

### POST /v1/admin/identity/directory/users

Creates a global directory user with a request-only temporary password. The
caller supplies `X-API-Key` and a provenance-bound platform-admin RS256 access
token. Normal session and token issuance remains blocked until the password is
changed through `POST /v1/accounts/changeTemporaryPassword`.

Request:

```json
{
  "email": "new@company.com",
  "temporaryPassword": "OneTimeSecret123"
}
```

Response 200:

```json
{
  "id": "uuid",
  "email": "new@company.com",
  "status": "ACTIVE",
  "authSource": "PASSWORD",
  "passwordChangeRequired": true,
  "createdAt": "2026-01-28T12:00:00Z"
}
```

`email` is normalized and globally unique. No tenant membership is created.

### POST /v1/accounts/lookup

Resolves an idToken to user identity metadata. codeQ producers call this endpoint to validate tokens. The token is provided in the request body.

Request:

```json
{
  "idToken": "<jwt>"
}
```

Response 200:

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

The response includes `role` when the user has one. When multi-tenant mode is active, `tenantId` is present. Downstream services use these two fields to enforce admin operations and tenant scoping without issuing further calls.

### POST /v1/accounts/update

Updates email or password (or both) for the authenticated user. The idToken in the payload identifies the caller.

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

### POST /v1/accounts/delete

Deletes the authenticated user. The idToken in the request identifies the user.

Request:

```json
{"idToken":"<jwt>"}
```

Response 200: empty JSON object.

### POST /v1/accounts/sendOobCode

Generates an out-of-band code for password reset or email sign-in. The `requestType` field binds the code to a consumption endpoint. The server persists this type alongside the code and rejects codes presented to the wrong endpoint.

| `requestType` | Consumed by |
|---|---|
| `PASSWORD_RESET` | `/v1/accounts/resetPassword` |
| `EMAIL_SIGNIN` | `/v1/accounts/signInWithOobCode` |

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

The code expires after 15 minutes. The code is single-use: after consumption the server deletes it, and subsequent attempts fail with 401.

For `EMAIL_SIGNIN` the server returns 200 regardless of whether the email maps to an account. This prevents account enumeration. Clients must not treat a 200 as proof that an account exists.

Tikti does not currently dispatch email or enqueue a notification job. Returning
`oobCode` is a temporary compatibility contract for a trusted server-side
orchestrator that performs the real delivery. Successful code-bearing responses
set `Cache-Control: no-store`, `Pragma: no-cache`, and
`X-Tikti-OOB-Delivery: external-required`. The code must not be exposed to a
browser, URL, application log, trace, metric, or audit event.

### POST /v1/accounts/signInWithOobCode

Authenticates a user with an out-of-band code generated by `/v1/accounts/sendOobCode` using `requestType=EMAIL_SIGNIN`. This enables passwordless sign-in: a user follows a link containing the code and obtains an idToken without entering a password.

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

| Status | Condition |
|--------|-----------|
| 401 | Code is invalid, expired, consumed, bound to a different email, or has a mismatched `requestType`. |
| 400 | Request body is malformed. |

### POST /v1/tenants/{tenantId}/oob/send

Generates and persists an OOB code scoped to a tenant, then returns the `oobCode` so that an external orchestrator (for example a Cadence workflow) can deliver it through the Notifications Service.

This compatibility route requires the service credential only in `X-API-Key`
and a strict RS256 Bearer. A tenant-local caller needs
`code-admin:identity:write` with signed `tid` exactly equal to `{tenantId}`;
cross-tenant orchestration requires provenance-bound platform-admin authority.
Query-string API keys, legacy HS256 tokens and role-only claims are rejected.

This endpoint does not itself dispatch a message. It uses the same
`external-required` compatibility and no-cache response headers documented for
`sendOobCode`; removing `oobCode` requires a real, verified dispatcher and a
versioned migration for the current orchestrator.

For `EMAIL_SIGNIN`, the server creates a user record when the email does not yet exist and scopes the user to the tenant in the path.

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

| Status | Condition |
|--------|-----------|
| 400 | `tenantId` or request body is invalid. |
| 403 | User is suspended or not allowed for the tenant. |
| 404 | `PASSWORD_RESET` and the user does not exist. |
| 500 | Server cannot persist the OOB code. |

### POST /v1/accounts/resetPassword

Resets a password using an out-of-band code. The code must have been issued with `requestType=PASSWORD_RESET`.

Request:

```json
{
  "oobCode": "uuid",
  "newPassword": "new-secret"
}
```

Response 200: empty JSON object.

## Administrative user lifecycle

Admin endpoints for user status and token revocation operate on arbitrary users, unlike `delete` which operates on the caller. These endpoints require an admin token.

### POST /v1/accounts/status

Sets user status. Valid values are `ACTIVE`, `INACTIVE`, and `SUSPENDED`. A suspended user cannot sign in and cannot exchange tokens.

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

The server logs the actor, the tenant context when applicable, and the status transition.

### POST /v1/accounts/revoke

Revokes tokens for a user by incrementing the stored token version. Tokens carry a `ver` claim; the server rejects tokens whose `ver` does not match the stored version.

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

The implemented model has one `tokenVersion` on the global user record; it has
no independently versioned tenant session. Therefore `scope` may be omitted or
must be `global`, and `tenantId` must be omitted. `scope=tenant`, any non-global
scope, or any non-empty `tenantId` returns 400 before the version is incremented.
Global revocation updates one user record in O(1). Tenant-only revocation requires
a future versioned storage, token-claim, and validation contract.

## Token exchange

### POST /v1/accounts/token/exchange

Exchanges an identity token for an RS256 access token. codeQ workers use this endpoint to obtain tokens carrying scopes and event types.

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

The server verifies the `idToken` using HS256 or RS256 depending on configuration. `tenantId` must reference a membership belonging to the token subject. `audience` must be a registered client identifier. `scopes` must be a subset of the union of role permissions and client-allowed scopes. `eventTypes` are validated against tenant or client policy.

Response 200:

```json
{
  "accessToken": "<rs256-jwt>",
  "tokenType": "Bearer",
  "expiresIn": 3600
}
```

Error cases:

| Status | Condition |
|--------|-----------|
| 401 | idToken is invalid. |
| 403 | Scopes exceed permissions or membership is missing. |
| 400 | Audience is unknown or request body is malformed. |

## JWKS

### GET /.well-known/jwks.json

Returns the RS256 public keys used to verify access tokens.

Response 200:

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

The response includes all active public keys. The server sets cache headers so that relying parties do not fetch the key set on every request.

## SAML 2.0 federation endpoints

Tikti acts as a SAML 2.0 Service Provider. The SAML endpoints live outside the `/v1/` prefix because they follow the SAML HTTP binding specifications rather than the JSON API conventions used by the identity endpoints. These endpoints handle browser redirects and form posts; only `/saml/metadata` and `/saml/discover` return machine-readable responses directly.

### GET /saml/metadata

Returns the SP EntityDescriptor as XML. No authentication is required.

The document contains the entity ID (`{issuerBaseUrl}/saml`), the Assertion Consumer Service URL (`{issuerBaseUrl}/saml/acs`), the Single Logout URL (`{issuerBaseUrl}/saml/slo`), and the SP signing certificate.

Response content-type: `application/samlmetadata+xml`.

Response 200: XML EntityDescriptor conforming to SAML 2.0 Metadata (OASIS saml-metadata-2.0-os).

Error cases:

| Status | Condition |
|--------|-----------|
| 500 | SP signing certificate cannot be loaded. |

### GET /saml/login/:tid

Initiates SP-initiated SSO for the tenant identified by `:tid`. The server loads the tenant IdP metadata from Redis at key `saml:idp:{tid}`, builds an AuthnRequest signed with RSA-SHA256 using HTTP-Redirect binding, stores the request ID in Redis at key `saml:req:{id}` with a 300-second TTL, and returns a 302 redirect to the IdP SSO URL.

Query parameters:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `RelayState` | No | URL to redirect the browser to after authentication completes. |

Response 302 with the following query parameters appended to the IdP SSO URL:

| Parameter | Value |
|-----------|-------|
| `SAMLRequest` | Deflated, base64-encoded AuthnRequest XML. |
| `RelayState` | Passed through from the request, or a server default. |
| `SigAlg` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` |
| `Signature` | RSA-SHA256 signature over the query string. |

Error cases:

| Status | Condition |
|--------|-----------|
| 404 | No IdP metadata exists in Redis for the given tenant. |
| 500 | AuthnRequest signing fails. |

### POST /saml/acs

Assertion Consumer Service. Receives the SAML Response via HTTP-POST binding. The browser submits this request as a form post generated by the IdP.

Form parameters:

| Parameter | Description |
|-----------|-------------|
| `SAMLResponse` | Base64-encoded SAML Response XML. |
| `RelayState` | URL passed through from the login request. |

The server validates the assertion in 10 steps, in order:

1. InResponseTo matches a request ID stored in Redis (`saml:req:{id}`).
2. Destination matches the ACS URL (`{issuerBaseUrl}/saml/acs`).
3. Status code is `urn:oasis:names:tc:SAML:2.0:status:Success`.
4. Response XML signature is verified against the IdP signing certificate.
5. If the assertion is encrypted, the server decrypts it with the SP private key.
6. Assertion XML signature is verified against the IdP signing certificate.
7. Issuer matches the IdP entity ID stored for the tenant.
8. Audience restriction includes the SP entity ID.
9. Time bounds (NotBefore, NotOnOrAfter) are checked with a 120-second clock skew tolerance.
10. SubjectConfirmationData is validated (Recipient, NotOnOrAfter, InResponseTo).

On success the server:

- Deletes the request ID from Redis (`saml:req:{id}`).
- Records the assertion ID for replay protection (`saml:seen:{AssertionID}`, TTL 3600 seconds).
- Provisions the user via JIT if the user does not yet exist in the tenant.
- Stores the session index in Redis for Single Logout.
- Issues an HS256 idToken with the `amr` claim set to `saml`.
- Returns 302 to the RelayState URL with the idToken in a `Set-Cookie` header.

Error cases:

| Status | Condition |
|--------|-----------|
| 400 | `SAMLResponse` is missing or cannot be decoded. |
| 401 | Any of the 10 validation steps fails. |
| 403 | Assertion ID has been seen before (replay). |
| 500 | idToken signing fails. |

### GET /saml/logout/:tid

Initiates SP-initiated Single Logout for the tenant identified by `:tid`. The server builds a LogoutRequest signed with RSA-SHA256 and redirects the browser to the IdP SLO URL.

Response 302 to the IdP SLO URL with a signed LogoutRequest in query parameters.

Error cases:

| Status | Condition |
|--------|-----------|
| 404 | No IdP metadata exists for the given tenant. |
| 500 | LogoutRequest signing fails. |

### GET|POST /saml/slo

Handles IdP-initiated logout. GET receives a LogoutRequest from the IdP. POST receives a LogoutResponse after an SP-initiated logout round-trip. In both cases the server validates the signature, clears the session index from Redis, and returns a response to the IdP.

For GET (LogoutRequest): the server parses the request, terminates the session, and responds with a signed LogoutResponse via redirect.

For POST (LogoutResponse): the server validates the response status and clears local session state.

Error cases:

| Status | Condition |
|--------|-----------|
| 400 | SLO message cannot be parsed. |
| 401 | Signature validation fails. |

### GET /saml/discover

Email-domain discovery. Given an email address, returns the tenant ID whose IdP is configured for that email domain. Login hint flows use this endpoint to route users to the correct IdP without requiring them to select a tenant.

Query parameters:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `email` | Yes | Email address to look up. |

Response 200:

```json
{
  "tenantId": "tenant-1",
  "idpEntityId": "https://idp.example.com/saml"
}
```

Error cases:

| Status | Condition |
|--------|-----------|
| 400 | `email` parameter is missing or malformed. |
| 404 | No tenant is configured for the email domain. |

## Tenant management (admin)

These endpoints use an explicit target tenant and require `X-API-Key` plus a
scoped RS256 bearer.

### PUT /v1/admin/identity/tenants/{tenantId}

Creates a tenant without overwrite. The path ID must equal the canonical slug;
creation returns 201, an identical replay returns 200, and conflicting metadata
returns 409.

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

### GET /v1/admin/identity/tenants/{tenantId}

Returns tenant metadata. Requires ADMIN or TENANT_ADMIN for the tenant.

### GET /v1/admin/identity/tenant-inventory

Returns the global inventory with `local-tenant` projected as the unique
`MASTER` named `Code Foundry`, followed by alphabetically ordered `WORKLOAD`
tenants. A query-string API key is rejected.

## Identity directory and access contract (internal admin)

Canonical administration lives under `/v1/admin/identity`. Directory lists are
bounded and secret-free. A workload administrator's prefix search returns only
members of its signed tenant; exact normalized email is the only external-user
resolver. Direct and group access uses explicit tenant routes under
`/access-assignments`, with monotonic versions and quoted ETag/If-Match
protection. Effective access exposes direct or group provenance. Old membership
HTTP routes are removed; legacy membership data is retained only as input until
the bounded startup backfill records its authoritative completion marker.

## Client management (admin)

### POST /v1/admin/tenants/{tenantId}/clients

Creates a client for token exchange. The response includes the generated client secret. The secret is returned once; subsequent reads do not expose it.

Request:

```json
{
  "clientId": "codeq-worker",
  "type": "SERVICE",
  "allowedGrantTypes": ["token_exchange"],
  "defaultScopes": ["codeq:claim","codeq:result"]
}
```

## Role management (admin)

### PUT /v1/admin/tenants/{tenantId}/roles/{roleName}

Creates a role and its permissions.

Request:

```json
{
  "permissions": ["codeq:admin","codeq:claim","codeq:result"]
}
```

## Identity V2 cutover

Old tenant, membership, role, and client admin aliases are intentionally
removed. Consumers must use the canonical explicit-target routes; the cutover
does not delete stored identity or access data.
