# 05 Multi-tenant Authorization

This document specifies how Tikti evaluates authorization in a multi-tenant environment. The algorithm is deterministic, remains stable across releases, and is expressed in prose and pseudocode.

## Authentication method independence

The authorization algorithm does not branch based on authentication method. An idToken issued through SAML 2.0 federation passes through the same authorization path as an idToken issued through password authentication. The algorithm evaluates `tid`, membership, roles, and scopes identically regardless of whether the token carries `amr: password` or `amr: saml`. This guarantee holds because the SAML flow terminates by issuing the same HS256 idToken that the password flow issues; downstream authorization has no visibility into the authentication method and does not need it.

## Tenant context resolution

Every tenant-scoped operation executes within a tenant context. The system resolves tenant context in a fixed order and uses the first resolved value as authoritative: first the `tid` claim in the token, then the `X-Tenant-Id` request header, then the `tenantId` field in the request body.

If no tenant context can be resolved, the request fails with 400. If a tenant context is resolved but does not correspond to an existing tenant, the request fails with 404. If a tenant context is resolved but the user does not hold a membership in that tenant, the request fails with 403.

The `tid` claim takes precedence because it is cryptographically bound to the token. Headers and body fields exist to support legacy or transitional flows but are validated against membership with the same strictness.

## SAML JIT provisioning and membership

Users provisioned through SAML Just-In-Time (JIT) provisioning receive a membership scoped to the tenant whose IdP authenticated them. The JIT-provisioned membership carries the default role set configured for that tenant's SAML integration. Once provisioned, the membership is indistinguishable from a membership created through any other method. The authorization algorithm treats JIT-provisioned users and manually provisioned users identically.

## Role types and scope expansion

Tikti defines three categories of roles. Global roles apply across all tenants; `ADMIN` is the canonical example. Tenant roles apply within a single tenant; `TENANT_ADMIN` is the canonical example. Resource roles apply to a resource server, such as `CODEQ_ADMIN` or `CODEFLOW_EXECUTOR`.

Each role expands into a fixed set of scopes. `CODEQ_ADMIN` expands to `codeq:admin`, `codeq:claim`, and `codeq:result`. Role definitions are static mappings stored in the roles repository. Role expansion is deterministic. The system does not permit dynamic or implicit scope generation without explicit role definitions because that would make authorization non-deterministic.

### Strict tenant role integrity

The immutable role API and strict tenant token canary accept only canonical tenant roles: the Redis hash field and role name must match, `scope` must be `TENANT`, `tenantId` must match the requested tenant, `resourceId` must be empty, and permissions must be sorted and unique. Exact reads reject malformed JSON, duplicate or unknown fields, nulls, trailing content, and any contract mismatch. A conflicting or corrupt existing role is never overwritten by an idempotent PUT.

The `code-admin:` namespace is reserved. Tikti embeds Code Admin scope policy `2026-08-10.1` with SHA-256 `93cdb76942b6aa7ce445ac5b4ab3f58980216afde0c6f31fb63a286835d99cd7`; only entries explicitly marked tenant-assignable may appear in tenant roles. Unknown, global, mixed, and tenant-bound but non-assignable Code Admin scopes fail closed during role writes, exact reads, and strict token expansion. Permissions outside `code-admin:` retain the existing syntax contract because Tikti does not yet have a complete offline registry for those namespaces.

`tenantScopedTokenClaimsV1` validates the compiled policy before opening Redis and derives authorization only from exact memberships and exact roles. It does not expand the global user role, `companyId`, or roles carried by an authentication assertion. With the flag off, legacy role and token routes keep their existing behavior.

The fixed Code Admin `tenant-admin` session is the narrow exception for `code-admin:features:write`. For a protected target tenant, Tikti still requires an exact active membership and the managed `code-admin-api` client ceiling, but it may add that one scope from a signed, persisted home role of `ADMIN` or `COMPANY_ADMIN`. It never adds the scope for an employee and does not store it in a custom tenant role. This change requires no data migration; rollback is the previous Tikti image, which restores denial without modifying memberships or roles.

Global membership administration is provenance-bound. The legacy exchange issues `code-admin:tenants:admin` only for a user whose persisted role is `ADMIN` and marks that access token with `tikti_platform_privilege=platform-admin`. The membership v2 route requires the scope, role, and issuance marker together. `COMPANY_ADMIN` remains compatible with unrelated legacy scopes but cannot obtain or replay a global tenant-administration capability.

Membership projection ownership is a storage invariant, not a route flag. All legacy server writers and `tikti-bootstrap` atomically check both v2 markers before mutating a pair, even when the v2 write route is disabled. Once v2 owns a pair, legacy create, update, and delete fail closed until an audited reconciliation removes that ownership; rolling deployments and route rollback therefore cannot reopen a legacy-only write path.

Before the Admin consumes exact role reads for a tenant, operators must census and backfill its stored roles to this contract; this read barrier applies even while the token flag is off. Repeat the check before adding the tenant to the strict canary allowlist. Roll back token issuance by removing the tenant from the allowlist or disabling the flag; do not delete role records or fall back to permissive reads in a privileged UI.

## Authorization decision algorithm

Authorization is a function of token claims, tenant membership, role definitions, and requested scopes. The inputs are: `token` claims (`sub`, `iss`, `aud`, `scope`, `tid`), `tenantId` resolved from token or request context, `requiredScopes` for the endpoint, and `resourceAudience` expected by the endpoint.

```text
1. Validate token signature and standard claims (iss, exp, iat).
2. Validate audience: token.aud must match resourceAudience.
3. Resolve tenantId (tid or request context).
4. Verify membership of token.sub in tenantId.
5. Resolve role set:
   a. global roles from token or user record
   b. tenant roles from membership
   c. resource roles from membership or resource assignment
6. Expand roles into permissions (scopes).
7. Verify requiredScopes ⊆ permissions.
8. If all checks pass, authorize.
```

A token with a valid signature but missing required scopes is denied. A token with valid scopes but a mismatched `aud` is denied. A token with a valid `aud` and scopes but no tenant membership is denied, unless the endpoint is global (such as an admin tenant creation endpoint). This rule prevents cross-tenant access.

## Complexity analysis

Let `r` be the number of roles assigned to a membership and `p` the total number of permissions across those roles. Role expansion requires `r` lookups and produces a permission set of size `p`. The permission check is a set inclusion test between required scopes (size `s`) and the permission set (size `p`).

- Role lookup: O(r), each lookup is O(1) in Redis.
- Permission union: O(p).
- Scope subset check: O(s + p).

In practice, `r` and `p` are bounded by policy (`r <= 10`, `p <= 100`), so the total runtime is O(1) per request.

## Global admin override

Global admins may override tenant membership for administrative endpoints but not for resource operations. A global `ADMIN` may access tenant management endpoints regardless of membership. A global `ADMIN` may not access resource server endpoints (codeQ, codeflow) without a tenant context and scopes. This bounds administrative privileges to explicit intent and auditable context.

## Token content and enforcement

Authorization is enforced using claims, not by trusting request parameters. The `scope` claim is authoritative for permissions. The `role` claim in an idToken is advisory, used for lookup responses and compatibility; it does not authorize resource access. Access tokens used for resource servers must include `scope`.

The `aud` claim must be enforced. A token minted for a different audience must be rejected even if scopes overlap. This prevents token replay across services.

## Example: codeQ worker authorization

A codeQ worker claims tasks. The endpoint requires `codeq:claim` scope and expects `aud=codeq-worker`. The token must include `eventTypes` that cover the requested commands. The authorization decision verifies: `aud == codeq-worker`, `scope` contains `codeq:claim`, `eventTypes` includes the command requested by the worker, and `tid` exists with the user holding membership in that tenant. If any check fails, the request is denied.

## Example: tenant admin role expansion

The tenant role `TENANT_ADMIN` expands to `tenants:read tenants:write users:invite roles:assign`. A user with that role can create and manage users in the tenant but cannot request codeQ scopes unless additional resource roles are assigned. This separation prevents privilege escalation across resources.

## Audit requirements

Authorization decisions must be auditable. Each decision logs `tenantId`, `subject` (user id), `aud`, required scopes and whether they were satisfied, and decision result (allow or deny). This log is necessary for security reviews and incident response.
