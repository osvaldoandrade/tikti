# ADR 0005: Use projected workload identity for bounded account brokering

## Status

Accepted for the Bereia rollout on 2026-08-25.

## Context

Bereia needs end-user password signup and signin through its API BFF. Existing
public Tikti account endpoints use API keys and accept authorization dimensions
that are appropriate for administrative clients but too broad for one tenant
workload. Copying an API key into the workload would create a long-lived secret
and make rotation and blast radius depend on application configuration.

The workload already receives a short-lived projected Kubernetes
ServiceAccount token. Tikti already verifies that issuer and JWKS, but the
generic workload exchange does not create users or exact memberships.

## Decision

Add an opt-in workload-account broker with an allowlist of at most 16 exact
clients. Each entry binds one tenant, `workload-<tenant>` namespace,
ServiceAccount/audience, non-administrative role, sorted audience-prefixed
scopes and a 60-3600 second lifetime. The server rejects configuration unless
the same tenant is enabled for tenant-scoped claims and the exact projected
ServiceAccount can be verified.

Tikti reconciles the exact role and a service client marked
`workload-account-bff` at startup, with only token exchange and the configured
scopes. The optional bootstrap job calls the same reconciler. Existing
incompatible objects fail startup or bootstrap instead of mutation or scope
broadening. A retired tenant is never recreated by this path.

Two canonical POST-only endpoints are enabled only when the broker is
configured:

- `/v1/workloads/accounts/register` creates or safely replays an active
  password user and ensures one exact tenant access assignment;
- `/v1/workloads/accounts/session` verifies password and effective tenant role,
  then issues a short-lived tenant-scoped RS256 access token to the BFF.

The same controllers also accept the two exact production-edge aliases
`/identity/v1/workloads/accounts/register` and
`/identity/v1/workloads/accounts/session`. The alias is required because the
identity edge preserves its public namespace when proxying this contract. It
does not create a prefix route, add methods, or change authorization; both
forms authenticate the same projected workload token before processing user
credentials.

Every request must contain exactly one projected-token Bearer header. Tikti
verifies issuer, JWKS signature, audience, expiry, namespace, ServiceAccount
and subject before reading credentials. Requests can supply only email and
password. Unknown fields and oversized bodies/tokens fail closed. Responses
are non-cacheable, use stable opaque errors and carry the contract marker
`workload-account-bff-v1`.

The BFF, not Tikti, owns the browser cookie. Tikti returns the access token only
to the authenticated workload; no token is persisted in application storage or
exposed to browser JavaScript.

## Security consequences

- There is no API key or static client secret in the workload.
- A stolen projected token expires quickly and is useful only for the exact
  configured subject and broker operations; it cannot choose another tenant,
  role, audience or scope.
- Registration races are reconciled by rereading the winning email record. A
  mismatched password or assignment is an opaque conflict, never an adoption.
- If assignment creation fails after a new user is created, Tikti attempts the
  bounded compensating user deletion and reports an opaque unavailable error.
- Tokens, passwords and projected credentials must never be logged.

## Private-cluster public-key distribution

Conveste's private K3s API is unreachable from the MASTER Tikti Pod. The
installation may pin the K3s **public** ServiceAccount JWKS in its reviewed
Helm values and mount it read-only at
`/app/etc/workload-jwks/<clusterRef>.json`. The matching provider uses an exact
`file://` URL and no bearer token. Tikti applies the same bounded JWKS parser,
RS256 signature check, issuer, audience, expiry and Kubernetes subject checks
used for HTTPS providers. Only the installation owns this file; a tenant
workload cannot publish its own trust material.

The Conveste `make deploy` preflight compares the installed public keys and
issuer to the live K3s OIDC endpoints before changing MASTER resources. On a
signing-key rotation, update the installation-owned key set first and retain
both public keys during the overlap; otherwise stop deployment and keep the
broker disabled until a token signed by the new key verifies. This adds no
private signing key or static workload credential to Tikti or source control.

## 2026-09-26 directory-authority amendment

The current Tikti application supplies its identity-directory repository to the
broker. Registration writes an exact user access assignment through
`PutAccessAssignment`; session reads effective tenant roles through
`GetEffectiveTenantRoles`. The legacy membership writer is not used in this
runtime. The chart therefore requires tenant-scoped claims and the client's
exact tenant allowlist but leaves the unrelated exact-membership HTTP read and
write flags off. Those routes require a separate pagination HMAC Secret and do
not authorize broker registration or session. Broker tests cover directory
assignment, session issuance, and denial after the exact role is removed. Tikti
startup now reconciles the installation-owned role and managed audience before
serving the broker. This is idempotent, detects ownership conflicts and keeps
the optional bootstrap job on the same reconciliation code.

## 2026-10-03 registration replay and Kvrocks amendment

WeCare's public registration returned 503 from the broker for two requests on
2026-10-03. The response did not expose the internal failing stage. Source
inspection found two paths that could produce that result:

- Replaying an existing password identity whose direct tenant assignment
  contains the broker role plus independently granted administrative roles
  attempted to replace the assignment with the broker role alone. The directory
  correctly rejected this missing-version write, but the broker reported 503.
- New user creation used `EVALSHA` through go-redis `Script.Run`. Kvrocks 2.7 can
  return a nonstandard `ERR NOSCRIPT` response that prevents the client's
  automatic `EVAL` fallback. The directory already uses direct `EVAL` for its
  other cache-independent scripts.

Registration now accepts a replay only when the current direct assignment
already contains the broker's exact role. It does not change the assignment or
expand any scopes. An existing assignment without that role is an opaque 409
conflict. New account creation executes the existing atomic directory script
through direct `EVAL`; no data format or HTTP success contract changes.

The rollout keeps the broker's current allowlist and role configuration. Run
the repository suite and release the compatible Tikti image through the owning
installation, then observe broker registration status and application signup
without retaining submitted credentials. Roll back the image if registration
errors rise; do not delete accounts or assignments. A failed registration may
already have created a user, so account state must be checked before any manual
replay or repair.

## Rollout

1. Deploy the compatible image with the feature disabled and run the full
   password, SAML, workload-exchange and membership regression suites.
2. Enable one exact client and allow Tikti startup to reconcile its role and
   audience. Stop on any role/client conflict.
3. Prove valid register, replay and session plus invalid issuer, audience,
   namespace, ServiceAccount, subject, password, assignment, scope and request
   shape.
4. Expose only the two exact POST paths at the master edge with login rate
   limiting and identity-header sanitization.
5. Enable the BFF cookie endpoints and verify signup/signin/logout through the
   real public application origin.

## Rollback

Disable signup/signin at the application BFF first, then remove the broker
client and restore the previous compatible Tikti image. Do not add an API-key
fallback and do not delete users, assignments, roles or clients during rollback.
The retained records make a corrected registration replay idempotent.
The `/identity` aliases may be removed independently only after the public edge
rewrite has been proven with register and session requests through the real
application origin.
For the private-cluster extension, disable the exact broker client before
removing the pinned JWKS provider or file. Preserve users, assignments and the
PostgreSQL database during rollback.

## Alternatives considered

- Reuse public API-key account endpoints: rejected because the key is
  long-lived and broader than one workload subject.
- Let the BFF choose tenant, role or scopes: rejected because request metadata
  is not an authorization boundary.
- Store sessions in CefasDB: rejected because it would persist bearer material
  outside Tikti and duplicate token lifecycle ownership.
- Put signup/signin directly in the browser against Tikti: rejected because it
  exposes the identity backend and prevents the application from enforcing its
  same-origin HttpOnly session contract.
