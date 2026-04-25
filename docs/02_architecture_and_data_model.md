# 02 Architecture and Data Model

This document specifies Tikti's architecture and data model with enough precision to drive storage design, API behavior, and authorization logic. It includes data structures, key layout, and algorithmic complexity where decisions depend on scale. The target design assumes Redis as the primary store, but the model is storage‑agnostic and can be implemented over any key‑value database with hash primitives.

## Architectural layers

Tikti is structured into four layers. The HTTP layer handles JSON parsing, request validation, and response formatting. The service layer enforces business rules such as password verification, SAML assertion validation, membership checks, and scope evaluation. The repository layer manages persistence and provides deterministic reads and writes for identity, membership, tenant metadata, and SAML federation state. The cryptographic layer issues and validates tokens, handles key rotation, and exposes JWKS. These layers must remain separable because token policy and data policy evolve at different cadences. The HTTP layer must not embed authorization logic; authorization is centralized in the service layer and is driven by explicit inputs (token claims, tenant context, client configuration).

## Canonical entities

The canonical entities define the identity graph. They are represented as JSON objects and stored as immutable or append‑only structures when possible. Mutable fields must be explicit and versionable.

A Tenant represents a security boundary. A User represents a global identity. A Membership binds a User to a Tenant. A Role defines permissions and is scoped globally, to a tenant, or to a resource server. A Client defines an audience for access tokens. An API Key gates administrative endpoints. An OOB Code provides a single‑use mechanism for password resets and verification.

This model provides stable identity (User), stable boundary (Tenant), and composable authorization (Membership + Role). It separates authentication credentials (User.passwordHash) from authorization state (Membership.roles), which is required for multi‑tenant access control.

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

A user is global. Email must be globally unique. When a user is created through SAML JIT provisioning, the `amr` field is set to `"saml"`. The `amr` field is optional and absent for password‑created users.

```json
{
  "id": "uuid",
  "email": "admin@codecompany.com.br",
  "passwordHash": "bcrypt",
  "status": "ACTIVE",
  "amr": "saml",
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

The layout avoids full scans and enables O(1) lookups. Keys use explicit prefixes and tenant IDs to enforce isolation. For high cardinality data (users, memberships), a two‑step lookup avoids storing large indexes within a single hash. SAML federation keys follow the same prefix convention and are tenant‑scoped where applicable.

| Key pattern | Value | TTL | Complexity | Purpose |
|---|---|---|---|---|
| `tenants` (hash) | `{tenantId}` -> `{TenantJson}` | none | O(1) | Tenant registry |
| `users` (hash) | `{userId}` -> `{UserJson}` | none | O(1) | User registry |
| `userByEmail:{email}` | `{userId}` | none | O(1) | Email-to-user index |
| `memberships:{tenantId}` (hash) | `{userId}` -> `{MembershipJson}` | none | O(1) | Tenant-scoped memberships |
| `roles:{tenantId}` (hash) | `{roleName}` -> `{RoleJson}` | none | O(1) | Tenant-scoped roles |
| `clients:{tenantId}` (hash) | `{clientId}` -> `{ClientJson}` | none | O(1) | Tenant-scoped clients |
| `apiKeys:{tenantId}` (hash) | `{apiKeyId}` -> `{ApiKeyJson}` | none | O(1) | Tenant-scoped API keys |
| `oob:{code}` (hash) | `email`, `reqType`, `expiresAt` | 900 s | O(1) | One-time OOB codes |
| `saml:req:{id}` | Pending AuthnRequest state | 300 s | O(1) read/write/delete | Stores request ID so the Assertion Consumer Service can match `InResponseTo` |
| `saml:idp:{tenantId}` | Per-tenant IdP metadata: entityID, ssoURL, sloURL, cert, attributeMapping | none (persisted until admin removes) | O(1) lookup | IdP trust configuration per tenant |
| `saml:idx:NameID` | tenant, subject, SessionIndex | none | O(1) lookup | SAML session index for Single Logout; maps NameID to session state |
| `saml:seen:{AssertionID}` | flag | 3600 s | O(1) lookup/set | Assertion replay protection; prevents the same assertion from being consumed twice |

This layout enforces tenant scoping by key and prevents inter‑tenant data access without an explicit tenant ID. It supports O(1) membership checks, role resolution, and SAML request correlation.

## Lookup paths and complexity

The performance‑critical operations are lookup, sign‑in, token exchange, SAML assertion consumption, and membership evaluation. The following specifies the expected complexity for each.

### Sign‑in

Sign‑in requires an email lookup and bcrypt verification.

Algorithm:

```text
userId = GET userByEmail:{email}
user = HGET users userId
verify bcrypt(password, user.passwordHash)
```

Time complexity: O(1) for Redis lookups plus O(cost) for bcrypt verification. Bcrypt cost is a configured constant in the range 10-12. Memory usage is O(1) per request.

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

### SAML assertion consumption

The Assertion Consumer Service receives a SAMLResponse, validates it, and issues an idToken. The lookup path touches four SAML keys.

Algorithm:

```text
idpMeta = GET saml:idp:{tenantId}
reqState = GET saml:req:{InResponseTo}
validate assertion signature, timestamps, audience, InResponseTo
DEL saml:req:{InResponseTo}
replayCheck = GET saml:seen:{AssertionID}
if replayCheck exists: reject
SET saml:seen:{AssertionID} TTL 3600
upsert user by tenantId + subject (JIT provisioning, amr="saml")
SET saml:idx:NameID {tenantId, subject, SessionIndex}
issue idToken with sub, tid, amr
```

Time complexity: O(1) for each Redis operation. The total is 6 Redis round trips (2 reads, 1 delete, 1 replay check, 2 writes) plus XML signature verification.

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

User creation requires two writes: `HSET users` and `SET userByEmail:{email}`. To avoid dangling users, the service must perform cleanup if the second write fails. The implementation uses a best‑effort rollback. This yields eventual consistency under partial failure but maintains correctness because `userByEmail` is the canonical entry point. The same pattern applies to SAML JIT provisioning, where user creation and membership creation must both succeed or roll back.

Pseudo‑code:

```text
userId = uuid()
HSET users userId userJson
if SET userByEmail:{email} userId fails:
  HDEL users userId
  return error
```

This is O(1) and can be retried safely. The same pattern applies to membership creation, role assignment, and SAML IdP metadata writes.

## Password reset lifecycle

OOB codes are stored with an `expiresAt` timestamp. Validation must check both presence and expiration. The code is one‑time: after successful use, it is deleted. OOB expiration can be enforced at read time or by Redis TTL. The specification allows both; a TTL is recommended for safety but not required.

## Multi‑tenant invariants

The following invariants must hold at all times:

1. An email maps to a single userId.
2. A membership is scoped to exactly one tenant.
3. A role belongs to at most one tenant or resource.
4. Access tokens must include a tenant claim (`tid`) that refers to an existing membership.
5. Deleting a tenant removes memberships, clients, roles, API keys, and SAML IdP configuration scoped to that tenant.
6. A `saml:idp:{tenantId}` key binds exactly one IdP to one tenant. No tenant shares an IdP binding with another tenant.
7. A `saml:req:{id}` key expires after 300 seconds. The Assertion Consumer Service rejects any response whose `InResponseTo` has no matching request key.
8. A `saml:seen:{AssertionID}` key prevents assertion replay for 3600 seconds after first consumption.

These invariants enable deterministic authorization and prevent cross‑tenant access through stale or replayed records.
