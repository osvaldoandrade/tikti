# Architecture and Data Model

This document specifies Tikti’s architecture and data model with enough precision to drive storage design, API behavior, and authorization logic. It includes data structures, key layout, and algorithmic complexity where decisions depend on scale. The target design assumes Redis as the primary store, but the model is storage‑agnostic and can be implemented over any key‑value database with hash primitives.

## Architectural layers

Tikti is structured into four conceptual layers. The HTTP layer handles JSON parsing, request validation, and response formatting. The service layer enforces business rules such as password verification, membership checks, and scope evaluation. The repository layer manages persistence and provides deterministic reads and writes for identity, membership, and tenant metadata. The cryptographic layer issues and validates tokens, handles key rotation, and exposes JWKS. These layers must remain separable because token policy and data policy evolve at different cadences. The HTTP layer should not embed authorization logic; authorization is centralized in the service layer and is driven by explicit inputs (token claims, tenant context, client configuration).

## Canonical entities

The canonical entities define the identity graph. They are represented as JSON objects and stored as immutable or append‑only structures when possible. Mutable fields must be explicit and versionable.

A Tenant represents a security boundary. A User represents a global identity. A Membership binds a User to a Tenant. A Role defines permissions and is scoped globally, to a tenant, or to a resource server. A Client defines an audience for access tokens. An API Key gates administrative endpoints. An OOB Code provides a single‑use mechanism for password resets and verification.

This model provides stable identity (User), stable boundary (Tenant), and flexible authorization (Membership + Role). It also separates authentication credentials (User.passwordHash) from authorization state (Membership.roles), which is essential for multi‑tenant access control.

## Data model definitions

The following definitions describe minimum fields and semantics.

### Tenant

A tenant is identified by a stable UUID. A slug is used for human‑readable URLs but must not be the canonical identifier.

```json
{
  "id": "uuid",
  "slug": "codecompany",
  "name": "Code Company",
  "status": "ACTIVE",
  "createdAt": "2026-01-28T12:00:00Z"
}
```

### User

A user is global. Email must be globally unique.

```json
{
  "id": "uuid",
  "email": "admin@codecompany.com.br",
  "passwordHash": "bcrypt",
  "status": "ACTIVE",
  "createdAt": "2026-01-28T12:00:00Z"
}
```

### Membership

A membership binds a user to a tenant and defines tenant‑scoped roles.

```json
{
  "id": "uuid",
  "tenantId": "tenant-1",
  "userId": "user-1",
  "roles": ["TENANT_ADMIN","CODEQ_ADMIN"],
  "createdAt": "2026-01-28T12:00:00Z"
}
```

### Role

Roles expand into scopes. Each role is scoped to GLOBAL, TENANT, or RESOURCE.

```json
{
  "name": "CODEQ_ADMIN",
  "scope": "RESOURCE",
  "tenantId": "tenant-1",
  "resourceId": "codeq",
  "permissions": ["codeq:admin","codeq:claim","codeq:result"]
}
```

### Client

A client is a token consumer with an audience identifier.

```json
{
  "id": "codeq-worker",
  "tenantId": "tenant-1",
  "secretHash": "bcrypt",
  "type": "SERVICE",
  "allowedGrantTypes": ["token_exchange"],
  "defaultScopes": ["codeq:claim","codeq:result"],
  "status": "ACTIVE"
}
```

### API key

```json
{
  "id": "primary",
  "tenantId": "tenant-1",
  "keyHash": "bcrypt",
  "scopes": ["accounts:lookup","accounts:update"],
  "status": "ACTIVE"
}
```

### OOB code

```json
{
  "code": "uuid",
  "tenantId": "tenant-1",
  "userId": "user-1",
  "type": "PASSWORD_RESET",
  "expiresAt": 1769535814
}
```

The OOB `type` binds a code to a specific flow. Supported types are `PASSWORD_RESET` and `EMAIL_SIGNIN`.

## Redis key layout

The target layout avoids full scans and enables O(1) lookups. Keys use explicit prefixes and tenant IDs to enforce isolation. For high cardinality data (users, memberships), a two‑step lookup is used to avoid storing large indexes within a single hash.

```
# Tenants
HSET tenants {tenantId} {TenantJson}

# Users and email index
HSET users {userId} {UserJson}
SET userByEmail:{email} {userId}

# Memberships
HSET memberships:{tenantId} {userId} {MembershipJson}

# Roles
HSET roles:{tenantId} {roleName} {RoleJson}

# Clients
HSET clients:{tenantId} {clientId} {ClientJson}

# API keys
HSET apiKeys:{tenantId} {apiKeyId} {ApiKeyJson}

# OOB codes (one-time)
HSET oob:{code} email {email} reqType {type} expiresAt {unix}
EXPIRE oob:{code} 900
```

This layout enforces tenant scoping by key and avoids inter‑tenant data access without explicit tenant ID. It supports fast membership checks and role resolution with a small number of hash lookups.

## Lookup paths and complexity

The performance critical operations are lookup, sign‑in, token exchange, and membership evaluation. The following outlines the expected complexity.

### Sign‑in

Sign‑in requires an email lookup and bcrypt verification.

Algorithm:

```text
userId = GET userByEmail:{email}
user = HGET users userId
verify bcrypt(password, user.passwordHash)
```

Time complexity: O(1) for Redis lookups plus O(cost) for bcrypt verification. Bcrypt cost is a configured constant, typically 10–12. Memory usage is O(1) per request.

### Lookup

Lookup requires token parsing and a user fetch by email claim.

Algorithm:

```text
claims = verify idToken (HS256)
email = claims.email
userId = GET userByEmail:{email}
user = HGET users userId
return user identity fields
```

Time complexity: O(1) for Redis and O(1) for token verification.

### Membership resolution

Membership is resolved by tenant and user id.

Algorithm:

```text
membership = HGET memberships:{tenantId} {userId}
```

Time complexity: O(1).

### Role expansion

Roles expand to scopes by loading role definitions.

Algorithm:

```text
permissions = empty set
for each role in membership.roles:
  roleDef = HGET roles:{tenantId} {role}
  add roleDef.permissions to permissions
```

Time complexity: O(r) with r = number of roles, each role lookup is O(1). Scope set union is O(p) where p is total permission count. In practice r and p are small and bounded by policy.

## Consistency and atomicity

Redis does not provide multi‑key transactions by default. Operations that touch multiple keys must be structured to maintain invariants.

User creation requires two writes: `HSET users` and `SET userByEmail:{email}`. To avoid dangling users, the service must perform cleanup if the second write fails. The implementation uses a best‑effort rollback. This yields eventual consistency under partial failure but maintains correctness because `userByEmail` is the canonical entry point.

Pseudo‑code:

```text
userId = uuid()
HSET users userId userJson
if SET userByEmail:{email} userId fails:
  HDEL users userId
  return error
```

This is O(1) and can be retried safely. Similar patterns apply to membership creation and role assignment.

## Password reset lifecycle

OOB codes are stored with an `expiresAt` timestamp. Validation must check both presence and expiration. The code is one‑time: after successful use, it is deleted. OOB expiration can be enforced either at read time (current) or by Redis TTL. The specification allows both; a TTL is recommended for safety but not required.

## Multi‑tenant invariants

The following invariants must hold at all times:

1. An email maps to a single userId.
2. A membership is scoped to exactly one tenant.
3. A role belongs to at most one tenant or resource.
4. Access tokens must include a tenant claim (`tid`) that refers to an existing membership.
5. Deleting a tenant removes memberships, clients, roles, and API keys scoped to that tenant.

These invariants allow deterministic authorization and prevent cross‑tenant access through stale records.
