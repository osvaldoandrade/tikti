# Troubleshooting

This page aggregates recurrent failure modes from API, token, codeQ, and operations specs.

## Authentication Errors

- `401 invalid credentials`: verify email/password or OOB code validity and expiration.
- `401 invalid token`: verify signature, expiry, and issuer/audience configuration.
- `403 forbidden`: verify effective tenant scope expansion and required permission mapping.

Primary references:
- [API Specification](API-Specification)
- [Multi-Tenant Authorization](Multi-Tenant-Authorization)
- [Tokens and Keys](Tokens-and-Keys)

## OOB Flow Failures

- OOB code expired: regenerate with `sendOobCode`.
- OOB code already consumed: enforce single-use semantics and request a new code.
- Request type mismatch: ensure the second step uses the same requestType as issuance.

Primary references:
- [API Specification](API-Specification)
- [Unit Test Functional Matrix](Unit-Test-Functional-Matrix)

## codeQ Integration Failures

- `aud` mismatch: confirm token exchange audience is the codeQ resource server.
- missing `eventTypes`: ensure token exchange payload includes required event types for worker contexts.
- JWKS fetch/parse failures: verify `/.well-known/jwks.json` availability and key IDs.

Primary reference:
- [codeQ Integration](codeQ-Integration)

## Operational Incidents

- Elevated latency or errors: inspect Redis health and API rate limits.
- Authentication spike failures: inspect key rotation windows and issuer configuration.
- Audit gaps: verify structured logging includes actor, tenant, action, and request correlation.

Primary reference:
- [Operations and SLO](Operations-and-SLO)
