# Security Model

This page centralizes Tikti security decisions from the canonical specs.

## Identity and Access Tokens

- `idToken` is HS256 and used for first-party identity operations.
- `accessToken` is RS256 and used for resource-server authorization.
- `iss`, `aud`, `scope`, `tid`, `ver`, and optional `eventTypes` claims are mandatory according to the token class.

See full contract: [Tokens and Keys](Tokens-and-Keys).

## Multi-Tenant Authorization

Authorization is deterministic and tenant-aware.

- Tenant context is derived from token and request path.
- Role expansion produces an effective permission set.
- Access is granted only when required scopes are contained in effective scopes for the tenant.
- Global admin override is explicit and auditable.

See algorithm details: [Multi-Tenant Authorization](Multi-Tenant-Authorization).

## Key Distribution and Validation

- Public keys are published through `/.well-known/jwks.json`.
- Resource servers must validate signature, `iss`, `aud`, expiry, and scope semantics.
- Key rotation keeps overlapping validation windows to avoid downtime.

## Operational Security

- API key gate protects selected endpoints.
- Secrets (`apiKey`, `jwtSecret`, private keys) must be managed outside source control.
- Audit logs must include actor, tenant, action, and trace correlation.

See operational requirements: [Operations and SLO](Operations-and-SLO).
