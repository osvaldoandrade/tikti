# Operations and SLO

This document defines operational expectations for Tikti in production. It covers configuration, health behavior, rate limits, logging, auditing, and SLO targets. The requirements here are normative because they influence security and stability.

## Configuration and secrets

Tikti must load configuration from a YAML file and allow environment overrides. The minimum configuration required for production is:

- `apiKey`: API key used for protected endpoints. This should be stored hashed and compared securely.
- `redisAddr`: Redis address.
- `jwtSecret`: HS256 secret for idTokens.
- `issuerBaseUrl`: issuer string for all tokens.
- `defaultAudience`: audience for idTokens when not specified by client.
- `jwksPrivateKey`: RSA private key for RS256 signing.

Environment overrides must be supported for each field so that secrets can be delivered through a secret manager. The process must refuse to start if `issuerBaseUrl` or `jwksPrivateKey` is missing when RS256 is enabled.

Tikti does not own email delivery. OOB codes are generated and persisted by Tikti, while delivery is orchestrated externally (for example, by a Cadence workflow that calls Tikti and then calls the Notifications Service).

## Health endpoints

Tikti must expose two health endpoints.

- `/healthz` responds 200 if the process is alive.
- `/readyz` responds 200 only if Redis is reachable and if RSA keys are loaded.

This distinction is required to prevent traffic from being routed to a process that cannot validate or sign tokens.

## Rate limiting

Authentication endpoints are a primary target for brute‑force attacks. Default rate limits must be enforced per IP and per email.

Recommended defaults:

- `signIn` / `signInWithPassword`: 5 requests per minute per IP, 5 per minute per email.
- `signInWithOobCode`: 10 requests per minute per IP, 10 per minute per email.
- `token/exchange`: 5 requests per minute per user id.
- `lookup`: 60 requests per minute per API key.
- OOB endpoints: 3 requests per hour per email.

Rate limits must be enforced regardless of API key presence and must return 429 with a consistent error shape. Rate limit counters can be stored in Redis with TTL.

## Logging

All requests must be logged with a unique request ID. Authentication and authorization failures must log issuer, audience, tenantId (if resolved), and the reason for denial. Tokens, passwords, and secrets must never be logged. The logging format must be machine‑parseable (JSON) in production.

## Audit

Administrative operations must produce audit records. A record is required for tenant creation, role assignment, client creation, secret rotation, and user creation or deletion. The record must contain:

- timestamp
- actor user id
- tenant id (if applicable)
- action
- target id
- outcome (success or failure)

Audit records must be retained for at least 30 days. The storage can be Redis, a database, or an external log sink, but the retention requirement is mandatory.

## Metrics

Tikti must expose counters and latency metrics. At minimum:

- `tikti_signin_total`
- `tikti_signup_total`
- `tikti_token_exchange_total`
- `tikti_lookup_total`
- `tikti_auth_fail_total`
- `tikti_request_latency_seconds{route}`

Metrics should be exported in Prometheus format under `/metrics`.

## SLO targets

The service must meet latency and availability targets to ensure dependent services (codeQ) are stable.

- Sign‑in P95 <= 50ms at 50 RPS.
- Token exchange P95 <= 80ms at 50 RPS.
- Lookup P95 <= 30ms at 50 RPS.
- JWKS availability >= 99.9% monthly.

These targets assume Redis resides within the same region and has single‑digit millisecond latency.

## Incident response

If token verification fails due to JWKS unavailability, Tikti must still serve lookup for idTokens. This requires separating HS256 validation from RS256 key distribution. In the event of JWKS outage, RS256 tokens may fail validation in resource servers; therefore Tikti must keep JWKS highly available and cacheable.

If issuer configuration changes, all existing tokens become invalid. Therefore issuer changes must be treated as breaking changes and coordinated with downstream services.
