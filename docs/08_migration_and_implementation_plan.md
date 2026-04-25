# 08 Migration and Implementation Plan

This document defines a staged plan to evolve Tikti from a single-tenant, HS256-only system into a multi-tenant, RS256-capable identity provider with codeQ support and SAML 2.0 federation. Each stage is an independent unit of work with acceptance criteria. The plan maintains backward compatibility at every step.

## Stage 0: Baseline hardening

This stage establishes operational safety and error consistency before introducing new semantics.

Introduce `/healthz` and `/readyz` endpoints. `/readyz` must fail if Redis is unreachable or if cryptographic keys cannot be loaded. Normalize error responses to the JSON error shape while preserving the existing `error` field for backward compatibility. Add structured logging with request IDs on all endpoints.

Acceptance criteria: health endpoints return expected status codes in local and production environments. Existing clients continue to function and receive an `error` field on failures.

## Stage 1: Issuer and lookup extensions

This stage makes tokens verifiable by external services and extends lookup with role and tenant data.

Add `issuerBaseUrl` and `defaultAudience` to configuration. Include `iss` and `aud` claims in idTokens. Extend the `/lookup` response to include `role`, `tenantId`, and `status`.

Acceptance criteria: `signIn` returns tokens containing `iss` and `aud`. `lookup` returns `role` and `tenantId` when available. codeQ producer validation works without changes.

## Stage 2: RS256 signing and JWKS

This stage introduces RS256 signing for access tokens and publishes JWKS for downstream verification.

Introduce RSA key management with `kid` support. Implement `/.well-known/jwks.json` with cache-control headers. Add RS256 signing utilities and validation helpers.

Acceptance criteria: the JWKS endpoint returns a valid key set. RS256 tokens validate using the published JWKS. Key rotation completes without token verification failures.

## Stage 3: Multi-tenant domain

This stage splits identity from membership and enforces tenant boundaries.

Add Tenant and Membership entities with their respective storage. Introduce the `userByEmail` index to enforce global email uniqueness. Update user creation to assign a membership within a default tenant.

Acceptance criteria: users can belong to multiple tenants. Email uniqueness is enforced globally. Membership is required for tenant-scoped operations.

## Stage 4: Role and client registry

This stage formalizes permissions and client audiences.

Add the Role entity and role CRUD endpoints. Add the Client entity with secret rotation support. Define a scope registry and validation rules.

Acceptance criteria: roles resolve into scopes deterministically. Clients control allowed grant types and default scopes. Scope validation rejects unauthorized scopes.

## Stage 5: Token exchange

This stage issues scoped access tokens for resource servers and workers.

Implement `/v1/accounts/token/exchange`. Validate idToken, tenant membership, client configuration, and requested scopes before issuing an RS256 access token. Support the `eventTypes` claim for worker tokens.

Acceptance criteria: exchange returns RS256 tokens with `aud`, `scope`, and `tid`. codeQ workers can claim tasks using exchanged tokens.

## Stage 6: Data migration

This stage migrates legacy data into the multi-tenant layout.

Create a default tenant (`tenantId=default`). For each user in the legacy `users` hash, create a user record (if not present), a `userByEmail:{email}` index entry, and a membership in the default tenant.

Pseudo-code:

```text
for each (email, userJson) in HGETALL users:
  userId = userJson.id
  SET userByEmail:{email} userId
  HSET users userId userJson
  HSET memberships:default userId membershipJson
```

Complexity: O(n) for n users. Each iteration performs a constant number of Redis operations.

Acceptance criteria: all existing users can still sign in. Memberships exist for the default tenant. Lookup returns `tenantId` for migrated users.

## Stage 7: Authorization enforcement

This stage enforces tenant scope and audience validation on all endpoints.

Implement tenant context resolution and membership checks. Enforce `aud` and `scope` on all resource endpoints. Remove reliance on dev-only role headers in production paths.

Acceptance criteria: cross-tenant access is denied. Tokens with an invalid audience are rejected. Admin endpoints require the admin role.

## Stage 8: Verification

This stage proves correctness through tests.

Extend `test_tikti.py` to verify lookup role and token exchange. Add unit tests for token validation and role expansion. Add integration tests for JWKS and RS256 validation.

Acceptance criteria: all tests pass in CI. codeQ integration tests pass using real tokens.

## Stage 9: Rollout and monitoring

This stage deploys the multi-tenant system with monitoring.

Deploy to staging with RS256 enabled but idTokens still HS256. Validate JWKS availability and cache behavior. Roll out to production with monitoring of auth failures and latency.

Acceptance criteria: no increase in auth error rates beyond baseline. JWKS endpoint maintains 99.9% availability. Token exchange P95 latency meets the target defined in the operations document.

## Stage 10: SAML 2.0 federation

This stage adds SAML 2.0 SP-initiated SSO as defined in the SAML federation HLD (`docs/12_saml_federation_hld.md`). SAML federation is additive and does not require migration of existing users. Tenants that do not configure an IdP binding continue to use the password authentication path with no changes. Tenants that configure an IdP binding gain SAML login as an additional authentication method.

Deploy the SAML HTTP handler, assertion validator, JIT provisioner, and SLO handler. Register IdP trust relationships for tenants via the `saml idp register` CLI command. Generate SP metadata and distribute it to IdP administrators.

This stage can be deployed independently of the preceding stages, provided that Stage 3 (multi-tenant domain) and Stage 2 (RS256 signing) are already in place. No data migration is required because SAML users are provisioned via JIT on first login.

Acceptance criteria: SP-initiated SSO completes end-to-end for at least one IdP (Azure AD or Okta). The idToken issued after SAML login contains `amr: ["saml"]` and is accepted by the existing token exchange path. SLO round-trip completes at P95 under 5 seconds. SAML metrics and audit records are emitted as defined in the operations document. SP key rotation completes with zero failed requests under load.
