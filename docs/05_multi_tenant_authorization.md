# 05 Multi‑tenant Authorization

This document specifies how Tikti evaluates authorization in a multi‑tenant environment. The intent is to define a deterministic policy that can be implemented without ambiguity and that remains stable across releases. The algorithm is expressed in prose and in pseudocode; complexity is included where it impacts design.

## Tenant context resolution

Every tenant‑scoped operation must execute within a tenant context. The tenant context is resolved in the following order, and the first resolved value is authoritative:

1. The `tid` claim in the token.
2. The `X‑Tenant‑Id` request header.
3. The `tenantId` field in the request body.

If no tenant context can be resolved, the request fails with 400. If a tenant context is resolved but does not correspond to an existing tenant, the request fails with 404. If a tenant context is resolved but the user does not hold a membership in that tenant, the request fails with 403.

The `tid` claim is the preferred source because it is cryptographically bound to the token. Headers and body fields are accepted to support legacy or transitional flows but must be validated against membership just as strictly.

## Role types and scope expansion

Tikti defines three categories of roles:

- Global roles, which apply across all tenants. Example: `ADMIN`.
- Tenant roles, which apply only within a specific tenant. Example: `TENANT_ADMIN`.
- Resource roles, which apply only to a resource server (for example, `CODEQ_ADMIN` or `CODEFLOW_EXECUTOR`).

Each role expands into a fixed set of scopes. For example, `CODEQ_ADMIN` may expand to `codeq:admin`, `codeq:claim`, and `codeq:result`. The role definition is a static mapping stored in the roles repository, and role expansion must be deterministic. The system must not allow dynamic or implicit scope generation without explicit role definitions, because that would make authorization non‑deterministic.

## Authorization decision algorithm

Authorization is a function of token claims, tenant membership, role definitions, and requested scopes. The algorithm uses the following inputs:

- `token` claims (subject, issuer, audience, scopes, tenant id)
- `tenantId` resolved from token/header/body
- `requiredScopes` for the endpoint
- `resourceAudience` expected by the endpoint

The algorithm is:

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

The algorithm is strict. A token with valid signature but missing required scopes is denied. A token with valid scopes but a mismatched audience is denied. A token with valid audience and scopes but no tenant membership is denied, unless the endpoint is explicitly global (such as an admin tenant creation endpoint). This rule is essential to prevent cross‑tenant access.

## Complexity analysis

Let `r` be the number of roles assigned to a membership and `p` the total number of permissions across those roles. Role expansion requires `r` lookups and produces a permission set of size `p`. The permission check is a set inclusion test between required scopes (size `s`) and the permission set (size `p`).

- Role lookup: O(r), each lookup is O(1) in Redis.
- Permission union: O(p).
- Scope subset check: O(s + p).

In practice, `r` and `p` are small and bounded by policy (for example, `r ≤ 10`, `p ≤ 100`), so the total runtime is effectively O(1) per request.

## Global admin override

Global admins may override tenant membership for administrative endpoints but not for resource operations. This prevents an admin token from being used to access tenant‑scoped resources without explicit tenant context.

The override rules are:

- Global ADMIN may access tenant management endpoints regardless of membership.
- Global ADMIN may not access resource server endpoints (codeQ, codeflow) without a tenant context and appropriate scopes.

This ensures that administrative privileges are bounded by explicit intent and auditable context.

## Token content and enforcement

Authorization is enforced using claims, not by trusting request parameters. The `scope` claim is authoritative for permissions. The `role` claim in an idToken is advisory and is only used for lookup responses and for compatibility; it is not sufficient for resource authorization. Access tokens used for resource servers must include `scope` explicitly.

The `aud` claim must be enforced. It is not acceptable to accept a token minted for a different audience even if scopes overlap. This prevents token replay across services.

## Example: codeQ worker authorization

A codeQ worker wants to claim tasks. The endpoint requires `codeq:claim` scope and expects `aud=codeq-worker`. The token must include `eventTypes` that cover the requested commands.

An authorization decision must ensure:

1. `aud == codeq-worker`
2. `scope` contains `codeq:claim`
3. `eventTypes` includes the command requested by the worker
4. `tid` exists and user has membership in that tenant

If any check fails, the request is denied.

## Example: tenant admin role expansion

Suppose the tenant role `TENANT_ADMIN` expands to `tenants:read tenants:write users:invite roles:assign`. A user with that role can create and manage users in the tenant but cannot request codeQ scopes unless additional resource roles are assigned. This separation avoids accidental privilege escalation across resources.

## Audit requirements

Authorization decisions must be auditable. Each decision should log:

- `tenantId`
- `subject` (user id)
- `aud`
- required scopes and whether they were satisfied
- decision result (allow/deny)

This log is necessary for security reviews and incident response.
