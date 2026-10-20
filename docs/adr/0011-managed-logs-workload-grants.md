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

Four grants are supported:

| Grant | Access audience | Authority |
| --- | --- | --- |
| Ingest | `logs-ingest` | Only `logs:ingest`; `logs_collector` pins installation, cluster, SA and Pod lifetimes; no tenant |
| Resolve | `code-admin-logs-authority` | Exact service subject `runtime:logs-api`; no user scopes or tenant |
| Publish | `codeq-producer` | Only `codeq:publish`, one `<tenant>.cf-logs` topic |
| Subscribe | `codeq-worker` | Only abandon/claim/heartbeat/nack/result for the same one topic |

Queue grants use the existing ADR-0022 `codeq_binding` carrier, with the actual
ObservabilityConfig UID/generation as the grant lifetime. The retained tenant
must be ACTIVE. They cannot request the topic-management scope, wildcard topic,
another audience, or an unrelated ResourceBinding. Grants are not cached.

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
