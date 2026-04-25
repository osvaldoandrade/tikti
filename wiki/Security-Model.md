# Security Model

This page centralizes Tikti security decisions across token handling, tenant authorization, key distribution, SAML 2.0 federation, and operational controls.

## Identity and Access Tokens

Tikti issues two token types. The `idToken` uses HS256 and serves first-party identity operations. The `accessToken` uses RS256 and serves resource-server authorization. Both token types require the claims `iss`, `aud`, `scope`, `tid`, and `ver`. The `accessToken` may include an `eventTypes` claim when issued for worker contexts.

See full contract: [Tokens and Keys](Tokens-and-Keys).

## Multi-Tenant Authorization

Authorization is deterministic and tenant-aware. Tikti derives tenant context from the token and the request path. Role expansion produces an effective permission set for the authenticated principal. Access is granted only when the required scopes are a subset of the effective scopes for the tenant. Global admin override is explicit and recorded in the audit trail.

See algorithm details: [Multi-Tenant Authorization](Multi-Tenant-Authorization).

## Key Distribution and Validation

Tikti publishes public keys at `/.well-known/jwks.json`. Resource servers must validate signature, `iss`, `aud`, expiry, and scope semantics before accepting a token. Key rotation maintains overlapping validation windows so that tokens signed by the outgoing key remain valid until they expire.

## SAML 2.0 Federation Security

Tikti acts as a SAML 2.0 Service Provider and enforces controls at every stage of the authentication exchange.

### Signed AuthnRequests

Tikti signs all AuthnRequests using RSA-SHA256. The signature binds the request content to the SP private key so that an intermediary cannot alter the request destination, assertion consumer URL, or requested authentication context. Identity Providers that enforce signature verification on incoming AuthnRequests will reject any tampered request before prompting the user.

### Assertion Validation Pipeline

When Tikti receives a SAML Response, it executes a 10-step sequential validation pipeline. The steps run in order: (1) InResponseTo correlation against the original AuthnRequest ID stored in Redis, (2) destination URL match against the configured assertion consumer service, (3) SAML status code check, (4) response-level XML signature verification, (5) decryption of encrypted assertions using the SP private key, (6) assertion-level XML signature verification, (7) issuer match against the registered IdP entity ID, (8) audience restriction match against the SP entity ID, (9) time bounds check on NotBefore and NotOnOrAfter with a tolerance of ±120 seconds, and (10) SubjectConfirmationData validation including recipient and expiry. The first step that fails causes Tikti to reject the assertion. No subsequent steps execute after a failure.

### Replay Protection

Tikti tracks every processed assertion ID in Redis under the key `saml:seen:{AssertionID}` with a TTL of 3600 seconds. When a SAML Response arrives, Tikti checks whether the assertion ID exists in Redis before proceeding with validation. If the ID is already present, Tikti rejects the assertion. This prevents an attacker from replaying a captured SAML Response within the assertion lifetime.

### Certificate Pinning

Each tenant's IdP signing certificate is pinned at registration time via `tikti-cli saml idp register`. Tikti stores the certificate fingerprint and uses it to verify assertion signatures. Assertions signed by a certificate that does not match the pinned fingerprint are rejected. When an IdP rotates its signing certificate, the tenant administrator must re-register the IdP with the new certificate before federation resumes.

### Clock Skew Tolerance

Tikti applies a ±120-second tolerance when evaluating NotBefore and NotOnOrAfter conditions in SAML assertions. This tolerance accommodates clock drift between Tikti and the IdP. Assertions whose time bounds fall outside this window after applying the tolerance are rejected.

## Operational Security

Tikti gates selected endpoints behind an API key. Secrets including `apiKey`, `jwtSecret`, and private keys must be managed outside source control. Audit logs include actor, tenant, action, and trace correlation for every mutating operation. SAML authentication events — including AuthnRequest issuance, assertion validation outcomes, and replay rejections — are recorded in the same structured log pipeline.

See operational requirements: [Operations and SLO](Operations-and-SLO).
