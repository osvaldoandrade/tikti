# Troubleshooting

This page aggregates recurrent failure modes across authentication, OOB flows, SAML 2.0 federation, codeQ integration, and operations.

## Authentication Errors

A `401 invalid credentials` response indicates that the email/password combination or OOB code failed validation. Verify that the credentials are correct and that the OOB code has not expired. A `401 invalid token` response indicates that token validation failed. Confirm that the signature algorithm matches the expected key, that the token has not expired, and that the `iss` and `aud` claims match the server configuration. A `403 forbidden` response indicates that authorization failed after authentication succeeded. Verify the effective tenant scope expansion and confirm that the required permission is present in the expanded set.

Primary references: [API Specification](API-Specification), [Multi-Tenant Authorization](Multi-Tenant-Authorization), [Tokens and Keys](Tokens-and-Keys).

## OOB Flow Failures

When an OOB code has expired, regenerate it by calling `sendOobCode`. When an OOB code has already been consumed, request a new code — each code is single-use. When the second step of the OOB flow fails with a request type mismatch, confirm that the `requestType` parameter matches the value used during code issuance.

Primary references: [API Specification](API-Specification), [Unit Test Functional Matrix](Unit-Test-Functional-Matrix).

## SAML 2.0 Federation Failures

SAML federation introduces failure modes at each stage of the authentication exchange.

When assertion signature verification fails, the IdP signing certificate may have rotated. Retrieve the current certificate from the IdP metadata and re-register it using `tikti-cli saml idp register`. Tikti pins the IdP certificate at registration time and rejects assertions signed by any other certificate.

When Tikti rejects an assertion due to clock skew, the NotBefore or NotOnOrAfter timestamps fall outside the ±120-second tolerance window. Synchronize NTP on both the Tikti host and the IdP host. After synchronization, the user must re-authenticate because the rejected assertion cannot be resubmitted.

When attribute mapping errors occur, the IdP is sending attributes under URNs that differ from what Tikti expects. Review the attribute mapping in the IdP configuration and ensure that name, email, and group attributes use the URNs that the Tikti SP metadata declares.

When Tikti returns an InResponseTo mismatch, the original AuthnRequest ID has expired from Redis. Tikti stores AuthnRequest IDs with a TTL of 300 seconds. If the user takes longer than 300 seconds to complete authentication at the IdP, the correlation entry expires and Tikti cannot match the response to a request. The user must retry the login flow.

When Tikti rejects an assertion as a replay, the same assertion ID was submitted more than once. Tikti tracks processed assertion IDs in Redis under the key `saml:seen:{AssertionID}` with a TTL of 3600 seconds. A second submission of the same assertion within that window is rejected. This is expected behavior — each SAML assertion is single-use.

## codeQ Integration Failures

When a token exchange fails with an `aud` mismatch, confirm that the token exchange audience matches the codeQ resource server identifier. When the `eventTypes` claim is missing from a worker token, ensure that the token exchange payload includes the required event types. When JWKS fetch or parse operations fail, verify that `/.well-known/jwks.json` is reachable and that the key IDs in the JWKS document match the `kid` headers in issued tokens.

Primary reference: [codeQ Integration](codeQ-Integration).

## Operational Incidents

When latency or error rates increase, inspect Redis health and API rate limits. When authentication failures spike, check key rotation windows and issuer configuration for overlap gaps. When audit gaps appear, verify that structured logging includes actor, tenant, action, and request correlation fields.

Primary reference: [Operations and SLO](Operations-and-SLO).
