# 07 Operations and SLO

This document defines operational expectations for Tikti in production. It covers configuration, health behavior, rate limits, logging, auditing, metrics, SLO targets, and SAML federation operations. The requirements stated here are normative because they govern security and stability.

## Configuration and secrets

Tikti loads configuration from a YAML file and supports environment variable overrides for each field. Environment overrides exist so that secrets can be delivered through a secret manager rather than committed to source control.

The following fields must be present for a production deployment:

| Field | Purpose |
|---|---|
| `apiKey` | API key for protected endpoints, stored as a bcrypt hash and compared in constant time |
| `redisAddr` | Redis connection address |
| `jwtSecret` | HS256 signing secret for idTokens |
| `issuerBaseUrl` | Issuer string embedded in all tokens |
| `defaultAudience` | Audience claim for idTokens when the client does not specify one |
| `jwksPrivateKey` | RSA private key for RS256 signing |

When RS256 signing is enabled, the process must refuse to start if `issuerBaseUrl` or `jwksPrivateKey` is absent. This prevents a running instance from issuing tokens that downstream services cannot verify.

When SAML federation is enabled, the configuration must also include `saml.sp.cert` and `saml.sp.key` (the SP signing certificate and private key). These are loaded from disk at process start and held in memory. The process must refuse to start if either file is unreadable or contains an expired certificate.

Tikti does not own email delivery. OOB codes are generated and persisted by Tikti, and delivery is orchestrated externally (for example, by a Cadence workflow that calls Tikti and then calls the Notifications Service).

## Health endpoints

Tikti exposes two health endpoints. `/healthz` responds 200 if the process is alive. `/readyz` responds 200 only if Redis is reachable and RSA keys are loaded. When SAML is enabled, `/readyz` must additionally verify that the SP signing key is loaded and that at least one IdP record can be read from Redis. This distinction prevents a load balancer from routing traffic to an instance that cannot validate or sign tokens.

## Rate limiting

Authentication endpoints are a target for brute-force attacks. Rate limits must be enforced per IP and per email regardless of whether an API key is present. Responses that exceed the limit must return HTTP 429 with the standard error shape. Rate limit counters are stored in Redis with TTL-based expiry.

| Endpoint | Limit |
|---|---|
| `signIn` / `signInWithPassword` | 5 req/min per IP, 5 req/min per email |
| `signInWithOobCode` | 10 req/min per IP, 10 req/min per email |
| `token/exchange` | 5 req/min per user ID |
| `lookup` | 60 req/min per API key |
| OOB endpoints | 3 req/hour per email |
| `/saml/login/{tid}` | 10 req/min per IP |
| `/saml/acs` | 10 req/min per IP |

The SAML endpoints receive the same rate-limiting treatment as password-based authentication. The `/saml/acs` limit protects the assertion validation path, which performs XML parsing, signature verification, and Redis writes on each request.

## Logging

All requests must be logged with a unique request ID. Authentication and authorization failures must include issuer, audience, tenant ID (if resolved), and the reason for denial in the log entry. Tokens, passwords, secrets, and SAML assertion XML must never appear in logs. The logging format must be machine-parseable JSON in production.

SAML-specific log entries must include the tenant ID, the IdP entity ID, and the assertion validation outcome. Validation failures must log the step at which validation failed (for example, "signature invalid" or "audience mismatch") without logging the assertion content.

## Audit

Administrative operations must produce audit records. A record is required for tenant creation, role assignment, client creation, secret rotation, user creation or deletion, and SAML IdP registration or update.

Each audit record contains the following fields:

| Field | Description |
|---|---|
| `timestamp` | ISO 8601 UTC |
| `actorUserId` | User who performed the action |
| `tenantId` | Tenant scope (if applicable) |
| `action` | Operation name |
| `targetId` | Identifier of the affected resource |
| `outcome` | `success` or `failure` |

Audit records must be retained for at least 30 days. The storage backend can be Redis, a database, or an external log sink, but the retention requirement is mandatory.

### SAML audit events

Each SAML assertion decision (accept or reject) must produce a structured audit record. The record follows the schema defined in the SAML federation HLD and contains:

| Field | Description |
|---|---|
| `event` | `saml.assertion` |
| `tenantId` | Tenant that owns the IdP trust relationship |
| `requestId` | Tikti-generated request ID from the `AuthnRequest` |
| `nameId` | Subject identifier from the assertion (hashed, not raw PII) |
| `issuer` | IdP entity ID |
| `assertionId` | Assertion ID from the SAML response |
| `decision` | `accept` or `reject` |
| `reason` | Validation step that caused rejection, or `ok` |
| `durationMs` | Time from assertion receipt to decision |
| `ts` | ISO 8601 UTC timestamp |

The audit sink is the existing Tikti audit writer. One record is emitted per assertion, regardless of outcome. This provides a forensic trail for every federated authentication attempt.

## Metrics

Tikti exposes counters and latency histograms in Prometheus format under `/metrics`.

### Core metrics

| Metric | Type | Description |
|---|---|---|
| `tikti_signin_total` | counter | Sign-in attempts |
| `tikti_signup_total` | counter | Sign-up attempts |
| `tikti_token_exchange_total` | counter | Token exchange requests |
| `tikti_lookup_total` | counter | Lookup requests |
| `tikti_auth_fail_total` | counter | Authentication failures |
| `tikti_request_latency_seconds{route}` | histogram | Request latency by route |

### SAML metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tikti_saml_authn_requests_total` | counter | `tid` | AuthnRequests generated |
| `tikti_saml_responses_total` | counter | `tid`, `result` | SAML responses received, labeled accept or reject |
| `tikti_saml_validation_failures_total` | counter | `tid`, `reason` | Assertion validation failures by step |
| `tikti_saml_jit_provisions_total` | counter | `tid` | Users created via JIT provisioning |
| `tikti_saml_logout_requests_total` | counter | `tid` | SLO requests initiated |
| `tikti_saml_logout_responses_total` | counter | `tid`, `result` | SLO responses received |
| `tikti_saml_response_validation_duration_seconds` | histogram | `tid` | Assertion validation latency |
| `tikti_saml_idp_cert_expiry_seconds` | gauge | `tid`, `subject` | Seconds until IdP certificate expiry |
| `tikti_saml_sp_cert_expiry_seconds` | gauge | | Seconds until SP certificate expiry |

The `reason` label on `tikti_saml_validation_failures_total` uses a closed set of values corresponding to the 10 validation steps defined in the SAML federation HLD (for example, `signature_invalid`, `audience_mismatch`, `expired`, `replay`). This allows operators to alert on specific failure modes without parsing logs.

## SLO targets

The service must meet latency and availability targets. These targets assume Redis resides within the same region with sub-2ms round-trip latency.

| Operation | Target |
|---|---|
| Sign-in | P95 <= 50ms at 50 RPS |
| Token exchange | P95 <= 80ms at 50 RPS |
| Lookup | P95 <= 30ms at 50 RPS |
| JWKS availability | >= 99.9% monthly |
| SAML assertion-to-idToken | P95 <= 150ms at 50 RPS (excluding IdP redirect time) |
| SLO round-trip | P95 <= 5s |

The SAML assertion-to-idToken target measures the time from when Tikti receives the `SAMLResponse` POST at `/saml/acs` to when it issues the HS256 idToken. This interval includes XML parsing, signature verification, replay detection, JIT provisioning, and token signing. It excludes the time the user spends at the IdP login page because that latency is outside Tikti's control.

## SAML key rotation

### SP key rotation

The `saml keys rotate` CLI command rotates the SP signing keypair using a two-step process. The operator first runs `saml sp rotate --prepare`, which generates a new keypair and publishes both the old and new certificates in the SP metadata endpoint. During this overlap period, the IdP can validate signatures made with either key. The operator then runs `saml sp rotate --commit`, which drops the old key from metadata and switches signing to the new key. The overlapping validity window prevents request failures during the transition. Helm values must be updated to reference the new key material before the commit step.

### IdP certificate refresh

When an IdP rotates its signing certificate, the tenant admin must update the pinned certificate in Tikti. This is done by running `saml idp register` (or `saml idp update`) with the new certificate or a fresh metadata URL. Tikti accepts assertions signed by both the old and new certificates for a 24-hour overlap period, after which it prunes the old certificate. The `tikti_saml_idp_cert_expiry_seconds` gauge provides advance warning of certificate expiry so that administrators can schedule the update before the IdP's old certificate expires.

## Incident response

If token verification fails due to JWKS unavailability, Tikti must still serve lookup for HS256 idTokens. This requires separating HS256 validation from RS256 key distribution. During a JWKS outage, RS256 tokens will fail validation in resource servers; therefore Tikti must keep the JWKS endpoint available and cacheable.

If issuer configuration changes, all existing tokens become invalid. Issuer changes must be treated as breaking changes and coordinated with downstream services.

If a SAML IdP becomes unreachable or begins returning errors, only tenants bound to that IdP are affected. The password authentication path remains operational for tenants that have it enabled. Operators should monitor `tikti_saml_validation_failures_total` for sustained increases in a single tenant, which may indicate an IdP certificate rotation that was not propagated to Tikti.
