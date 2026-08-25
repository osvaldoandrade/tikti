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
the same tenant is enabled for tenant-scoped claims, exact membership reads and
membership-v2 writes.

The bootstrap job creates the exact role if absent and ensures a service client
marked `workload-account-bff`, with only token exchange and the configured
scopes. Existing incompatible objects cause bootstrap failure instead of
mutation or scope broadening.

Two POST-only endpoints are enabled only when the broker is configured:

- `/v1/workloads/accounts/register` creates or safely replays an active
  password user and ensures one exact tenant membership;
- `/v1/workloads/accounts/session` verifies password and exact membership,
  then issues a short-lived tenant-scoped RS256 access token to the BFF.

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
  mismatched password or membership is an opaque conflict, never an adoption.
- If membership creation fails after a new user is created, Tikti attempts the
  bounded compensating user deletion and reports an opaque unavailable error.
- Tokens, passwords and projected credentials must never be logged.

## Rollout

1. Deploy the compatible image with the feature disabled and run the full
   password, SAML, workload-exchange and membership regression suites.
2. Enable one exact client and run bootstrap. Stop on any role/client conflict.
3. Prove valid register, replay and session plus invalid issuer, audience,
   namespace, ServiceAccount, subject, password, membership, scope and request
   shape.
4. Expose only the two exact POST paths at the master edge with login rate
   limiting and identity-header sanitization.
5. Enable the BFF cookie endpoints and verify signup/signin/logout through the
   real public application origin.

## Rollback

Disable signup/signin at the application BFF first, then remove the broker
client and restore the previous compatible Tikti image. Do not add an API-key
fallback and do not delete users, memberships, roles or clients during rollback.
The retained records make a corrected registration replay idempotent.

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
