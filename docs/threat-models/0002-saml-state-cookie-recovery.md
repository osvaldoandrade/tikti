# Threat model: SAML state-cookie recovery

## Scope

This delta covers the production browser path from a Google Workspace
HTTP-POST response to Tikti `/saml/acs`. It does not change IdP-initiated SSO,
assertion validation, tenant selection, role mapping, session lifetime, or
logout.

The protected assets are the browser-bound login request, signed SAML
assertion, tenant identity, and resulting Tikti session. An Internet attacker
may submit arbitrary form bodies, replay previously observed messages, embed
the ACS endpoint, or attempt to log a victim into an attacker-controlled
account.

## Trust boundaries

1. Google Workspace and the public Internet cross into Tikti at `/saml/acs`.
2. The browser carries an HttpOnly state cookie across the IdP round trip.
3. Tikti consumes the one-time request record from Kvrocks before it creates a
   session.

## STRIDE analysis

| Threat | Risk | Control | Verification |
|---|---|---|---|
| Spoofing | An attacker posts a valid response from the attacker's login into a victim browser. | Tikti still requires the `__Host-` state cookie on the same-origin repost and validates `InResponseTo`, issuer, audience, destination, signature, and subject confirmation. The host-only prefix prevents a sibling domain from supplying a colliding state cookie. | Missing-cookie retry test rejects; legacy-cookie collision test uses only the host-bound cookie; production audit must record `accept` only after request correlation. |
| Tampering | An attacker changes `SAMLResponse`, `RelayState`, or repost fields. | `html/template` escapes values; CSP restricts scripts to a nonce and forms to the same origin; the existing cryptographic pipeline rejects changed assertions. | Unit tests inspect escaping and CSP; existing validator suites remain green. |
| Repudiation | Operators cannot distinguish recovery from ordinary ACS traffic. | `tikti_saml_state_cookie_recovery_total{result}` counts repost, success, and failure without identity or payload labels. Existing audit events record the final accept or reject decision. | Metrics test gathers all three bounded label values. |
| Information disclosure | A proxy or browser cache retains a signed assertion. | The repost response sets `Cache-Control: no-store`, `Pragma: no-cache`, and `Referrer-Policy: no-referrer`; Tikti never logs the form values. | Header tests and diff review. |
| Denial of service | A client forces infinite reposts or amplified processing. | Tikti allows one repost marker and rejects the next missing-cookie request before signature validation. The existing pending request remains one-time and expires after 300 seconds. | Retry-without-cookie test returns `request_not_found`; no redirect or repost loop occurs. |
| Elevation of privilege | Repost data supplies a tenant or role. | The repost carries only the original SAML fields. Tikti derives the tenant from the consumed request and roles from the verified assertion mapping after all validation checks. | Existing tenant-isolation and attribute-mapping tests remain green. |

## Verdict

**GO.** The recovery path preserves the browser-state gate, adds no trust
source, logs no assertion data, and fails closed after one retry.
