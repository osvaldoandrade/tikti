# Tenant runtime authority

CFP-102 implements the Tikti producer defined by Code Foundry CRDs RFC 0012,
section 6. Tikti alone owns tenant lifetime, state and retained tombstones.
`GET /v1/internal/tenants/{tenantId}/runtime-state` reads exactly one Redis hash
field and performs no mutation. It returns exactly `schemaVersion`, `tenantId`,
`tenantEpoch`, `state`, `observedAt` and `nonce`, bounded to 4 KiB. States are
`ACTIVE`, `DISABLED`, `RETIRED` and `ABSENT`; absence has an empty epoch and is
never retirement evidence.

Enable only with `tenantRuntimeAuthorityV1: true` (Helm
`config.tenantRuntimeAuthorityV1`, environment `TENANT_RUNTIME_AUTHORITY_V1`).
The default is false. This flag is independent of SQL admission, browser token,
target discovery and group features. It requires the existing mounted private
`apiKey`. It issues no machine token and grants no new write operation.

The machine request has exactly one nonempty `X-API-Key`, one
`X-Code-Foundry-Tenant-Runtime: tenant-runtime/v1`, and one
`X-Code-Foundry-Tenant-Runtime-Nonce` consisting of 64 lowercase hexadecimal
characters. The caller generates 32 fresh random bytes for each request; the
producer validates and echoes the nonce. Credentials are compared using
constant-time digest comparison. Browser `Origin`, `Cookie` and `Authorization`,
queries, bodies, transfer encoding, duplicate/comma-joined headers, noncanonical
paths and every method except GET are rejected before a storage read.

The private namespace and rejected aliases are registered in `NewApplication`
before the browser CORS middleware. Success and errors have `Cache-Control:
no-store`, no browser CORS grant, and bounded JSON. Error codes are
`TenantRuntimeInvalidRequest` (400), `TenantRuntimeUnauthorized` (401),
`TenantRuntimeUnsupported` (404) and `TenantRuntimeUnavailable` (503).
Headers, keys, display names and raw storage errors never enter this response.
Ordinary access logs record only the route pattern and sanitized metadata.

Only Redis nil means ABSENT. Empty, oversized or invalid records fail closed,
including unknown, duplicate, case-aliased or null members, ID/slug mismatch,
unsupported status and invalid lifetime/retirement timestamps. Existing canonical
RFC3339Nano numeric offsets remain readable; redundant timestamp forms are
rejected. The epoch is lowercase SHA-256 of UTF-8
`codefoundry/tenant-lifetime/v1`, NUL, exact ID, NUL, and the original birth
timestamp normalized to UTC RFC3339Nano. Observation time is captured before
the HGET and returned in UTC. Consumers must retain that original time and
validate the maximum two-minute lease without renewal from a cache.

Bootstrap `Create` validates the retained record inside each WATCH attempt,
preserves its original birth and disabled state, and marshals inside the
transaction. Retirement remains monotonic and keeps the original epoch.
`CreateIfAbsent` cannot repair corrupt records or reuse retired IDs. The existing
public `Get` and `GetExact` projections continue to hide retained tenants; no
stored/public Tenant field or read-triggered backfill was added.

## Migration and rollback

Deploy the additive canonical CRD contract, then this producer, then the matching
API client and negotiated agents, followed by SQL runtime consumers. Enabling
SQL still requires the separately verified installation tuple and capacity gates.
This implementation changes no Service, NetworkPolicy, Pod count or capacity.
The existing shared-key holders may read minimal tenant state. Internal HTTP
relies on the verified control-plane network, DNS and trusted nodes; external
API-to-Tikti connections require verified HTTPS. Effective isolation is a
production activation gate, not evidence supplied by a rendered chart.

Before SQL inventory exists, the default-off endpoint permits staged rollout.
Once SQL or retained bindings exist, rollback may disable SQL admission while
retaining this authority endpoint, the compatible API reads and immutable
lifetime write semantics. Do not downgrade below that floor or delete retained
identity fields. Identity/runtime restoration across lifetimes requires a
separate reviewed operation; this producer cannot authorize data deletion.

## Executed contract checks

`make test-sql-contract` runs strict repository, actual HTTP, CORS/header/path,
redaction, lifetime and SAML regression tests, including isolated **real
redis-server** processes and deterministic WATCH/retirement races. Redis is a
required test dependency; it is never silently replaced or skipped. Each process
uses a private Unix socket, no Redis TCP listener and no persistence, and is
terminated and reaped during cleanup. `make test`, `make helm-test`, `make lint`,
`make security` and the declared race suite remain required independently.

The API's integration test can run `go run ./testdata/tenant-runtime-authority`.
The fixture starts the actual `NewApplication` HTTP route and repository, with
browser CORS installed in production order. The executable is excluded from
production entrypoints and has no HTTP mutation/test bypass.

Control uses JSON lines on stdin, limited to 16 KiB per line. The first line is
`{"apiKey":"test-only-key","enabled":true}`; stdout returns `{"url":"http://127.0.0.1:..."}`.
Subsequent commands return `{"ok":true}` or a static `{"error":"FixtureCommandFailed"}`:

- `{"action":"seed","tenantId":"payments","state":"ACTIVE","createdAt":"2024-01-01T00:00:00Z"}` invokes real Create/CAS; `DISABLED` is also accepted.
- `{"action":"retire","tenantId":"payments"}` invokes the actual retained retirement.
- `{"action":"raw","tenantId":"payments","raw":"..."}` installs an explicit bounded corruption fixture.
- `{"action":"outage"}` stops the fixture's Redis to prove failure handling.

EOF closes HTTP, Redis clients and the isolated Redis process. Control values,
credentials and raw storage never appear in stdout/stderr. Consumer tests map
their fixed trusted origin to this local HTTP listener through a test-only
transport; production origin restrictions remain enforced.
