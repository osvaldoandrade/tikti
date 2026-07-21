# ADR-0001: Exchange projected Kubernetes identities for provider tokens

**Status:** Accepted

**Date:** 2026-07-21

## Context

Code Admin controllers need tenant-bound provider tokens, but static API keys or
tenant administrator tokens would be long-lived, difficult to rotate, and easy
to reuse outside the originating workload. Kubernetes already projects bounded
ServiceAccount JWTs with an issuer, audience, namespace, and subject.

## Decision

Tikti exposes `POST /v1/workloads/token/exchange`. It validates the projected
JWT against the configured Kubernetes issuer and JWKS, requires audience
`tikti-workload-exchange`, and compares the verified namespace and
ServiceAccount with the JWT subject.

Authorization is independent of authentication. Redis stores an explicit
subject binding containing the permitted tenant, target audience, and scope.
The first supported grant is exactly `codeq-producer` with `codeq:admin`.
After revocation commits to Redis, subsequent exchange requests are denied.

Successful exchanges produce an RS256 token with `iss`, `aud`, `sub`, `tid`,
`scope`, `iat`, `exp`, and `jti`. Access-token lifetime is at most one hour and
defaults to five minutes. Subject and access tokens are never persisted or
logged.

## Options considered

### Static controller credentials

Rejected because credentials would be long-lived, tenant-specific secrets in
controller configuration and would not prove the originating workload.

### Kubernetes TokenReview

Deferred. It requires Tikti to hold Kubernetes API credentials and couples the
identity service to cluster availability. Offline issuer/JWKS verification
keeps the trust boundary explicit and supports controlled key caching.

### OIDC/JWKS verification with explicit bindings

Selected. It provides cryptographic workload authentication while keeping
tenant authorization revocable and independent from token claims.

## Consequences

- Operators must configure the cluster issuer and JWKS URL and maintain
  workload bindings.
- Tikti must refresh JWKS safely during signing-key rotation.
- Unknown key IDs are refresh-rate-limited and JWKS redirects are rejected to
  prevent unauthenticated requests from amplifying outbound traffic or crossing
  the configured trust boundary.
- An unavailable JWKS endpoint blocks uncached exchanges rather than falling
  back to an unverified token.
- Existing user token exchange remains backward compatible.

## Rollback

Revoke the affected binding, scale down the controller, and restore the last
compatible Tikti image. Do not restore static controller tokens. Tokens already
issued expire within the configured lifetime, never longer than one hour.
