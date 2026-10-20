# ADR 0011: managed Logs workload grants

Date: 2026-10-19
Status: accepted for implementation; disabled by default
Task: CFP-115

## Context

Managed collectors and a shared Logs runtime need short-lived credentials. A
cluster-agent token, an admin token or one tenant's application identity must
not become a credential for reading or publishing another tenant's logs.

## Decision

Extend the existing `POST /v1/workloads/token/exchange` with the mutually
exclusive `logsGrant` selector. Verify the projected subject with the existing
provider/JWKS authority and audience `tikti-workload-exchange`. Require canonical
namespace, ServiceAccount, SA UID, Pod UID, provider clusterRef and expiry.
Request identity comes from that verified subject, never from caller metadata.

The `workloadIdentity.managedLogs` configuration is default-off. An enabled
installation pins a bounded, credential-free Code Admin authority URL. The
client accepts only the exact route `/internal/v1/logs-grants:authorize`, HTTPS
or the configured Kubernetes service origin. Requests are bounded, not retried
or redirected, and grant responses must be non-cacheable and match the request.
The authority receives a signed service assertion for audience
`code-admin-logs-authority`, subject `tikti:logs-exchange`, lifetime 60 seconds.

The original grants are supported unchanged:

| Grant | Access audience | Authority |
| --- | --- | --- |
| Ingest | `logs-ingest` | Only `logs:ingest`; `logs_collector` pins installation, cluster, SA and Pod lifetimes; no tenant |
| Resolve | `code-admin-logs-authority` | Exact service subject `runtime:logs-api`; no user scopes or tenant |
| Publish | `codeq-producer` | Only `codeq:publish`, one `<tenant>.cf-logs` topic |
| Subscribe | `codeq-worker` | Only abandon/claim/heartbeat/nack/result for the same one topic |

### Dedicated native store grants (2026-10-20)

`CefasBootstrap` and `CefasRuntime` additionally use the exact fixed audience
`code-admin-logs-store`. Neither accepts tenant, kind, config or CodeQ selectors.
Scopes must equal the operation's fixed set without missing, extra, duplicate or
whitespace-normalized entries; the signer uses fresh server-defined scope sets,
not caller-selected permissions. Bootstrap receives `cefas:table:create` and
`cefas:table:describe`. Runtime receives describe, item read/write/delete and
query on `logs-events`, and item read/write on `logs-state`. The API must grant
that exact operation to the verified native principal and return installation,
cluster and grant UID/generation only. It separates the bootstrap native
ServiceAccount UID from all other roles. Existing grants never imply store
rights, and the human exchange rejects this reserved audience even for ADMIN,
custom clients, default scopes or legacy requests.

Tokens use the existing RS256/JWKS signer, verified workload subject, jti, exact
audience, fixed scope and original-subject-capped <=300-second lifetime. They
contain no tenant, role, CodeQ, collector or human authority. The native store
already supports JWT/JWKS validation and needs no auth code change. Since
global describe also reads CDC, this credential is only for a dedicated
Logs-only datastore. No general workload audience/binding, new endpoint, field,
dependency, signing key, long-lived secret or automatic platform role is added.

The runtime exchanges its rotating projected subject on demand and retains
access tokens only in bounded memory. API/identity failure denies renewal; no
expired token, static fallback or human credential is used. Already issued
bearers remain valid until expiry plus configured native clock skew.

Activation installs the human-audience guard before enabling the native store
listener and grants. The guard prevents new issuance and does not invalidate a
previously issued human JWT. This source work observed neither historical
tokens nor an active dedicated Logs store; it does not inspect or expose token
inventories to claim retroactive revocation.

Queue grants use the existing ADR-0022 `codeq_binding` carrier. The optional
top-level `grantKind` defaults to `ObservabilityConfig`, with the actual enabled
config UID/generation as the grant lifetime. Only Subscribe may instead select
`LogRetentionPolicy`: `configUID`/`configGeneration` then identify the real
retained tenant policy `default`. This permits draining accepted batches after
the last source is deleted or disabled. The authority must match that current
native policy lifetime; missing, deleting, replaced or mismatched policies
refuse issuance. Publish cannot use a policy grant, and Ingest/Resolve accept
no kind selector. Unknown kinds or kind without `logsGrant` are refused.
The retained tenant must be ACTIVE. Queue grants cannot request the
topic-management scope, wildcard topic, another audience, or an unrelated
ResourceBinding. Grants are not cached.

Access tokens expire within 300 seconds and no later than the projected
subject; Resolve expires within 60 seconds. A subject with less than 30 seconds
remaining is refused. Rate and concurrency limits apply per identity and
installation. Raw tokens, authority bodies and provider errors are not logged.

## Compatibility and rollback

Omitted configuration leaves the existing exchange paths active and refuses
Logs grant attempts without falling through to legacy workload grants. Typed
JSON rejects unknown, duplicate or differently cased fields; canonical existing
request fields are unchanged. No signing key, role, IdP or credential migration
is introduced. Disable `managedLogs.enabled` to stop new grants, then allow at
most 300 seconds for issued access tokens to expire. Retain existing signing
keys while those tokens remain valid.

New Tikti with an older API cannot obtain native store grants; an old Tikti
refuses those new operations. The original four operations work unchanged in
either direction. Before downgrading the API, remove the two new principal
enums because older configuration validation refuses them. The shared version
and fields remain unchanged; this is a fail-closed additive private enum.

Human platform log reads use the new reserved
`code-admin:logs:platform:read` permission in scope policy `2026-10-19.1`
(SHA-256 `31e849fe03de6300bcce16ae568cd71acff14e2fd5e0f5e3196e1612fa4dda8d`).
It is global and cannot appear in tenant roles. There is no external `console:`
alias for this privilege. Every human token-exchange path, including legacy,
requires an explicit requested scope, the actual Code Admin audience/client
ceiling and current platform authority: allowlisted MASTER SAML principal, or
password administrator with an exact direct MASTER ADMIN assignment. Neither
an ADMIN role name nor client defaults alone grant the permission. Bearer
validation rechecks that platform authority after assignment removal.

## Verification

Service tests verify RS256 signatures, issuer, audience, kid, lifetime, precise
scope and carrier contents. Negative cases cover injected tenants, mixed grant
selectors, inactive tenants, noncanonical subjects, mismatched configuration
lifetimes and authority failure. HTTP tests cover redirection, cache headers,
body limits and strict JSON. The strict decoder has fuzz coverage. Local tests
do not establish production configuration or authenticated acceptance.
