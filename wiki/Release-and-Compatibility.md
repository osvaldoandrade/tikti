# Release and Compatibility

This page consolidates compatibility and rollout guarantees.

## Compatibility Contract

- API contracts must remain backward compatible unless explicitly versioned.
- Token claim semantics (`iss`, `aud`, `scope`, `tid`, `ver`) are stable contracts for integrators.
- Multi-tenant authorization behavior is deterministic and must not drift silently between releases.

## Rollout Strategy

Use the staged plan in [Migration and Implementation Plan](Migration-and-Implementation-Plan):

1. Hardening and issuer normalization.
2. RS256 signing and JWKS.
3. Multi-tenant domain and authorization.
4. Token exchange and integration validation.
5. Verification and monitored rollout.

## Release Checklist

- API regressions validated against [API Specification](API-Specification).
- Token validation matrix checked against [Tokens and Keys](Tokens-and-Keys).
- Unit quality gates satisfied from [Unit Test Execution Backlog](Unit-Test-Execution-Backlog).
- Operational readiness validated via [Operations and SLO](Operations-and-SLO).
