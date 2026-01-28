# 08 Migration and Implementation Plan

This document defines a staged plan to evolve Tikti from its current single‑tenant, HS256‑only system into a multi‑tenant, RS256‑capable identity provider with codeQ support. Each stage is an independent unit of work with explicit acceptance criteria. The plan is designed to minimize downtime and maintain backward compatibility at every step.

## Stage 0: Baseline hardening

The objective is to ensure that the existing service has operational safety and consistent errors before introducing new semantics.

Actions:

- Introduce `/healthz` and `/readyz` endpoints. `/readyz` must fail if Redis is unreachable or if cryptographic keys cannot be loaded.
- Normalize error responses to the JSON error shape while preserving the existing `error` field.
- Add structured logging with request IDs.

Acceptance criteria:

- Health endpoints return expected status codes in local and production environments.
- Existing clients still function and receive an `error` field on failures.

## Stage 1: Issuer and lookup extensions

The objective is to make tokens verifiable by external services and extend lookup with role and tenant data.

Actions:

- Add configuration fields `issuerBaseUrl` and `defaultAudience`.
- Include `iss` and `aud` in idTokens.
- Extend `/lookup` response to include `role`, `tenantId`, and `status`.

Acceptance criteria:

- `signIn` returns tokens containing `iss` and `aud`.
- `lookup` returns `role` and `tenantId` when available.
- codeQ producer validation works without changes.

## Stage 2: RS256 signing and JWKS

The objective is to introduce RS256 signing for access tokens and publish JWKS for downstream verification.

Actions:

- Introduce RSA key management with `kid` support.
- Implement `/.well-known/jwks.json` with caching headers.
- Add RS256 signing utilities and validation helpers.

Acceptance criteria:

- JWKS endpoint returns valid key set.
- RS256 tokens validate successfully using JWKS.
- Key rotation can occur without token verification failures.

## Stage 3: Multi‑tenant domain

The objective is to split identity from membership and enforce tenant boundaries.

Actions:

- Add Tenant entity and storage.
- Add Membership entity and storage.
- Introduce `userByEmail` index to enforce global email uniqueness.
- Update user creation to create membership within a default tenant.

Acceptance criteria:

- Users can belong to multiple tenants.
- Email uniqueness is enforced globally.
- Membership is required for tenant‑scoped operations.

## Stage 4: Role and client registry

The objective is to formalize permissions and client audiences.

Actions:

- Add Role entity and role CRUD endpoints.
- Add Client entity with secret rotation support.
- Define scope registry and validation rules.

Acceptance criteria:

- Roles resolve into scopes deterministically.
- Clients control allowed grant types and default scopes.
- Scope validation rejects unauthorized scopes.

## Stage 5: Token exchange

The objective is to issue scoped access tokens for resource servers and workers.

Actions:

- Implement `/v1/accounts/token/exchange`.
- Validate idToken, tenant membership, client configuration, and requested scopes.
- Support `eventTypes` claim for worker tokens.

Acceptance criteria:

- Exchange returns RS256 tokens with `aud`, `scope`, and `tid`.
- codeQ workers can claim tasks using exchanged tokens.

## Stage 6: Data migration

The objective is to migrate legacy data into the new multi‑tenant layout.

Actions:

- Create a default tenant (`tenantId=default`).
- For each user in the legacy `users` hash:
  - create a user record (if not already present)
  - create `userByEmail:{email}` index
  - create a membership in the default tenant

Pseudo‑code:

```text
for each (email, userJson) in HGETALL users:
  userId = userJson.id
  SET userByEmail:{email} userId
  HSET users userId userJson
  HSET memberships:default userId membershipJson
```

Complexity: O(n) for n users. Each iteration performs a constant number of Redis operations.

Acceptance criteria:

- All existing users can still sign in.
- Memberships exist for the default tenant.
- Lookup returns tenantId for migrated users.

## Stage 7: Authorization enforcement

The objective is to enforce tenant scope and audience validation consistently.

Actions:

- Implement tenant context resolution and membership checks.
- Enforce `aud` and `scope` on all resource endpoints.
- Remove reliance on dev‑only role headers in production paths.

Acceptance criteria:

- Cross‑tenant access is denied.
- Invalid audience tokens are rejected.
- Admin endpoints require explicit admin role.

## Stage 8: Verification

The objective is to prove correctness through tests.

Actions:

- Extend `test_tikti.py` to verify lookup role and token exchange.
- Add unit tests for token validation and role expansion.
- Add integration tests for JWKS and RS256 validation.

Acceptance criteria:

- All tests pass in CI.
- codeQ integration tests pass using real tokens.

## Stage 9: Rollout and monitoring

The objective is to deploy safely with measurable confidence.

Actions:

- Deploy to staging with RS256 enabled but idTokens still HS256.
- Validate JWKS availability and cache behavior.
- Roll out to production with monitoring of auth failures and latency.

Acceptance criteria:

- No increase in auth error rates beyond baseline.
- JWKS endpoint maintains 99.9% availability.
- Token exchange P95 latency under target.
