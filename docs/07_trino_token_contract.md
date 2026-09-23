# Trino token issuance contract

CFP-108 adds a dormant issuance contract on the existing account and workload
exchange routes. Application construction does not inject a Trino authority, so
all reserved `trino:` exchanges fail closed. CFP-111 must supply and independently
verify durable installation registration and current identity authorization
before activation. No new public registration API or runtime feature is active.

`TrinoIdentityAuthority` must check the exact active installation UID, current
ACTIVE tenant lifetime, current principal identity and explicit
`code-admin:trino:query` entitlement on each request. Its workload method receives
the verified projected subject with issuer, cluster, signed ServiceAccount UID
and bound Pod UID and must map those to the current Service UID; legacy CodeQ
name-only grants are insufficient. The returned
`TrinoWorkloadAuthorization` contains current Service-owned ServiceAccount and
Pod UIDs, independently read from authority rather than echoed from the token.
Issuance requires the signed ServiceAccount UID and compares both object UIDs
exactly; a same-name recreated account or Pod cannot inherit old tokens. Legacy
CodeQ tokens without UID claims retain their existing behavior. The
implementation must return an error on unavailable or stale authority and must
never accept principal/epoch claims from exchange request fields. It does not
own catalog ACLs: the query guard intersects the signed identity with catalog
permissions separately.

Issuance accepts one exact query scope and exact installation audience. It hashes
UTF-8 netstrings of installation UID, tenant ID, tenant epoch, subject kind and
subject UID into `trino_principal`. Tenant epoch is the unchanged lowercase
SHA-256 tenant-runtime/v1 lifetime value. User identity comes from the current
validated ID token and user record. Workload identity comes from the verifier
and authority mapping. Tokens expire within five minutes, with user expiry also
bounded by the source session. No native SQL credential enters a token.

Existing audiences retain their current token shape and lifetime. New claims
are confined to reserved Trino exchanges. Tenant-assignable Trino read/write
scopes govern API intent; neither implies query authority, and installation
mutation additionally requires platform ADMIN in MASTER scope.

Rollback before activation removes the dormant contract with no credential or
resource migration. After activation, CFP-111 retirement must disable new
issuance and drain query consumers before removing the authority/compatible
runtime; token expiry alone does not terminate already-running queries.
