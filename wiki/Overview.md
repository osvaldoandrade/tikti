> Canonical source: [`docs/01_overview.md`](https://github.com/osvaldoandrade/tikti/blob/main/docs/01_overview.md)
> Synced on: 2026-02-12

# Overview

This document defines the high‑level specification for Tikti, the identity service responsible for authentication and authorization across multiple tenants and resource servers. The text is normative: unless stated otherwise, statements use “must” to indicate required behavior and “should” to indicate strong recommendations. The goal is to be precise enough that two independent implementations converge on the same behavior.

Tikti provides three core capabilities. First, it authenticates users using email and password and issues identity tokens that represent the user’s authenticated session. Second, it authorizes access by issuing scoped access tokens whose audience targets a specific resource server, and by exposing a lookup endpoint that allows services to validate identity tokens when full JWT verification is not available. Third, it supports multi‑tenant membership so that the same user can be authenticated once and authorized against multiple tenants and resources without re‑registration.

The current system is a Firebase‑compatible API surface: `signIn`, `signInWithPassword`, `lookup`, `update`, `delete`, and OOB flows (password reset and email sign‑in). Tokens are HS256 signed using a shared secret. User records are stored in Redis keyed by email, and out‑of‑band codes are stored in a separate hash with expiration enforced at read time. These behaviors are preserved for compatibility, but Tikti is extended to include issuer and audience claims, a token exchange endpoint for RS256 tokens, and multi‑tenant membership and role evaluation.

## Scope and guarantees

The service must guarantee that every authenticated request maps to a stable user identity, that authorization decisions are deterministic, and that tokens are auditable and verifiable by external services. Tikti must provide a stable issuer string (`iss`) per deployment environment and must issue tokens with explicit audiences (`aud`) that identify the target resource server. This is mandatory for codeQ, which validates `aud`, `iss`, `exp`, and `scope` for worker access.

The service must be multi‑tenant. A tenant is an authorization boundary; a user can belong to multiple tenants with different roles and permissions. Tikti must never authorize a user for tenant‑scoped operations without an explicit tenant context. Token exchange requires a tenant membership check and produces access tokens containing a tenant identifier claim (`tid`). A token without `tid` is valid only for global operations such as self lookup, and even then only if the server policy allows it.

The service must remain compatible with existing clients that only understand identity tokens. This means `signIn` and `signInWithPassword` continue to return the same payload shape, `lookup` continues to accept the same payload, and the API key mechanism using `?key=` remains valid for protected endpoints. New fields added to responses must be additive and must not change the meaning of existing fields. Existing tokens signed with HS256 remain valid until their expiration; new access tokens and worker tokens are RS256 signed and verified through JWKS.

## Definitions

A tenant is a logical boundary that groups users, roles, and resources. A client is a logical consumer of tokens and maps to the `aud` claim in access tokens. A resource server is an API that validates access tokens; it enforces `aud` and `scope` and rejects mismatched tokens. A role is a named permission set; roles are expanded into concrete scopes. A scope is a permission string, such as `codeq:claim` or `codeq:result`, embedded in the `scope` claim as a space‑delimited string. A membership binds a user to a tenant and includes a set of roles. An idToken represents authenticated identity; an access token represents authorization to a resource server; a worker token is a specialized access token for codeQ workers with an `eventTypes` claim.

These definitions are not optional. Each request that performs a tenant‑scoped action must resolve a tenant context and must pass the authorization algorithm defined in `05_multi_tenant_authorization.md`. Each access token must include `aud`, `iss`, `exp`, `iat`, and `tid`. Each worker token must include `eventTypes` and a scope set that is a subset of the worker’s allowed permissions.

## Security model

Tikti must separate identity proof from authorization. Authentication is performed via password verification and results in an identity token. Authorization is performed by evaluating scopes and membership; it must not rely on client‑supplied metadata. All sensitive materials (passwords, API keys, private keys) must be stored as hashes or in secret managers. Passwords are stored using bcrypt, and API keys must be stored as bcrypt or HMAC hashes. Private keys for RS256 must never be returned by any endpoint.

Issuer (`iss`) and audience (`aud`) are enforced at every verification point. All services that consume tokens must treat `iss` as a fixed deployment identifier and must reject unknown issuers. Tikti must define a stable issuer per environment such as `https://api.storifly.ai` and must never change it without rotating all downstream validation. Audience values must be explicit and versioned if necessary to avoid breaking existing tokens.

## Multi‑tenant reasoning and invariants

A user may exist without any tenant memberships, but access tokens can only be issued for tenants where the user has a membership. Membership is the only source of truth for tenant authorization; a role claim in an idToken does not override membership constraints except for global admins. If a user is a global admin, the token exchange may permit cross‑tenant operations for administrative endpoints, but the tenant context must still be explicit in the request and logged for audit.

The system must maintain the invariant that an email maps to exactly one user identifier. This makes sign‑in deterministic and avoids ambiguous lookup results. Membership is many‑to‑many and is modeled independently from user creation. Deleting a user must delete all memberships. Deleting a tenant must remove all tenant‑scoped roles, clients, and memberships.

## Compatibility contract

The compatibility contract is strict: an existing integration that uses `signInWithPassword` followed by `lookup` must continue to succeed without modification. The response shape is extended to include `role`, `tenantId`, and `status`. Consumers that ignore unknown fields will continue to function. All endpoints must return JSON error objects using a stable shape even when the legacy system returned plain `{"error": "..."}`; the new error shape must be a superset so legacy clients can still read the `error` field.

## Example (identity token and lookup)

The following example shows a sign‑in call that returns an identity token, followed by a lookup call that includes role and tenant data. These examples are illustrative and are not exhaustive; full payloads are defined in `04_api_spec.md`.

```http
POST /v1/accounts/signInWithPassword?key=API_KEY
Content-Type: application/json

{"email":"admin@codecompany.com.br","password":"mypassword2","returnSecureToken":true}
```

```json
{
  "idToken": "<hs256-jwt>",
  "email": "admin@codecompany.com.br",
  "localId": "uuid",
  "expiresIn": 3600
}
```

```http
POST /v1/accounts/lookup?key=API_KEY
Content-Type: application/json

{"idToken":"<hs256-jwt>"}
```

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

## Design implications

This overview implies concrete implementation requirements: token exchange must be able to validate HS256 idTokens and produce RS256 access tokens; JWKS must be published at a fixed path; and all resource servers, including codeQ, must validate `iss` and `aud` and enforce scope checks. These requirements are non‑negotiable for multi‑tenant safety and must be applied consistently across all endpoints and all tenants.
