# SAML Troubleshooting Guide

This document covers every SAML login rejection reason defined in
HLD §19, the error-ID lookup procedure, and the four user-facing error
buckets from Appendix Q. Use it to diagnose failures reported by end
users or surfaced in server-side logs.

## Error-ID Lookup Procedure

When a SAML login fails, the user sees a neutral error page containing
a 12-character **Error ID** (e.g. `0196d3a1b2c3`). The same value is
returned in the `X-Tikti-Error-ID` response header. No internal reason
is shown on the page to prevent oracle attacks.

To find the root cause:

1. **Obtain the Error ID** — the user can read it from the error page, or
   you can extract it from the `X-Tikti-Error-ID` header in browser
   developer tools.

2. **Search server-side logs** — the Error ID appears in the structured
   audit log emitted for every assertion decision. Grep the application
   logs or your log aggregator:

   ```bash
   # Kubernetes
   kubectl logs -l app=tikti --all-containers | grep '<error-id>'

   # Plain journald
   journalctl -u tikti | grep '<error-id>'
   ```

3. **Read the audit record** — the matching JSON line contains the
   `reason` field (one of the 18 codes below), the `tid` (tenant), and
   the `requestID` that correlates with the original `AuthnRequest`.

4. **Match the reason code** — find the reason in the table below and
   follow the resolution steps.

## User-Facing Error Buckets (Appendix Q)

The server never exposes internal reason codes to the browser. Instead,
each reason maps to one of four **error buckets**, each with its own HTTP
status and neutral message.

| Bucket | HTTP Status | Message Shown to User | Reason Codes |
|---|--:|---|---|
| `bad_request` | 400 | "The sign-in request could not be processed. Please try again from the beginning." | `request_not_found`, `destination_mismatch`, `missing_attribute` |
| `forbidden` | 403 | "Your sign-in was not accepted. Please contact your administrator if this continues." | `request_replay`, `issuer_mismatch`, `status_not_success`, `audience_mismatch`, `signature_invalid`, `decrypt_failed`, `assertion_signature_invalid`, `clock_skew`, `subject_confirmation_mismatch`, `algorithm_disallowed`, `xxe_detected`, `signature_wrapping_detected` |
| `not_configured` | 404 | "Single sign-on is not configured for this application. Please contact your administrator." | `tid_unknown` |
| `internal` | 500 | "An unexpected error occurred. Please try again later or contact support." | `idp_metadata_stale`, `internal_error` |

If a user reports an error, identify the bucket from the page title or
HTTP status code, then look up the Error ID in server logs to find the
specific reason code.

## Rejection Reason Reference

### `bad_request` Bucket (HTTP 400)

---

#### `request_not_found`

**What it means:** The SAML response references an `InResponseTo` request
ID that does not exist in the request store (Redis key `saml:req:{id}`).

**Likely causes:**
- The user bookmarked or reloaded the ACS URL after the request expired
  (default TTL: 300 s).
- The request was already consumed by a previous response.
- Redis was flushed or restarted between the `AuthnRequest` and the
  response.

**Resolution:**
1. Ask the user to start the login flow again from the application.
2. If the issue is persistent, verify that the Redis instance backing the
   SAML request store is healthy and that its data is not being evicted
   prematurely.
3. Check that the `--request-ttl` (default 300 s) is long enough for your
   IdP's round-trip time.

---

#### `destination_mismatch`

**What it means:** The `Destination` attribute in the SAML response does
not match the SP's configured ACS URL.

**Likely causes:**
- The ACS URL registered in the IdP does not match `--acs-url` on the SP.
- A reverse proxy or load balancer is rewriting URLs.
- The SP was reconfigured with a new ACS URL but the IdP metadata was not
  updated.

**Resolution:**
1. Compare the `Destination` value in the SAML response (visible in
   base64-decoded `SAMLResponse`) with the SP's `--acs-url`.
2. Update the IdP's SSO app configuration so the ACS URL matches exactly,
   including scheme, host, port, and path.
3. If a proxy rewrites the `Host` header, configure it to preserve the
   original header or set `--acs-url` to the external URL.

---

#### `missing_attribute`

**What it means:** A required SAML attribute is absent from the assertion's
`AttributeStatement`.

**Likely causes:**
- The IdP is not releasing the attributes configured in the tenant's
  attribute map.
- Attribute names are case-sensitive and may differ between IdPs (e.g.
  `emailAddress` vs `email` vs
  `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`).

**Resolution:**
1. Decode the SAML response and inspect the `<AttributeStatement>` to see
   which attributes the IdP actually sends.
2. Compare them with the attribute map configured via
   `tikti saml idp register --attribute-map`.
3. Update either the IdP's attribute release policy or the SP's attribute
   map so they match.

---

### `forbidden` Bucket (HTTP 403)

---

#### `request_replay`

**What it means:** The assertion ID has already been seen within the replay
window (default: 1 hour). The `saml:seen:{assertionID}` key exists in
Redis.

**Likely causes:**
- The user submitted the same SAML response twice (e.g. browser back
  button, form resubmit).
- A network intermediary retried the POST to `/saml/acs`.

**Resolution:**
1. Ask the user to start a new login from the application.
2. No configuration change is needed — this is a security control working
   as intended.

---

#### `issuer_mismatch`

**What it means:** The `<Issuer>` element in the SAML response does not
match the `EntityID` stored in the IdP record for this tenant.

**Likely causes:**
- The IdP's entity ID changed (e.g. after reconfiguration or migration).
- The wrong IdP metadata was imported for this tenant.

**Resolution:**
1. Run `tikti saml idp show --tid <tenant>` to see the stored entity ID.
2. Compare it with the `<Issuer>` in the SAML response or the IdP's
   metadata XML.
3. Re-register or update the IdP:
   `tikti saml idp update --tid <tenant> --metadata-url <url>`.

---

#### `status_not_success`

**What it means:** The IdP returned a SAML `<StatusCode>` other than
`urn:oasis:names:tc:SAML:2.0:status:Success`.

**Likely causes:**
- The user failed authentication at the IdP (wrong password, MFA denied).
- The IdP denied access based on a conditional-access or authorization
  policy.
- The IdP encountered an internal error.

**Resolution:**
1. Check the `<StatusCode>` and `<StatusMessage>` in the SAML response
   for details.
2. Review the IdP's sign-in logs for the corresponding authentication
   attempt.
3. This is usually an IdP-side issue — resolve it there.

---

#### `audience_mismatch`

**What it means:** The `<AudienceRestriction>` in the assertion does not
include the SP's entity ID.

**Likely causes:**
- The SP entity ID configured in the IdP does not match `--entity-id` on
  the SP.
- The IdP has multiple SAML apps and the response was routed to the wrong
  one.

**Resolution:**
1. Compare the `<Audience>` value in the decoded assertion with the SP's
   `--entity-id`.
2. Update the IdP's Audience / Entity ID field to match exactly.

---

#### `signature_invalid`

**What it means:** The XML signature on the SAML response failed
verification against the IdP's signing certificate.

**Likely causes:**
- The IdP rotated its signing certificate but the SP still has the old
  certificate cached.
- The SAML response was modified in transit.
- The IdP metadata was not refreshed after a certificate rollover.

**Resolution:**
1. Force a metadata refresh:
   `tikti saml idp fetch --tid <tenant>`.
2. If the IdP does not publish metadata at a URL, re-register with the
   new metadata XML:
   `tikti saml idp update --tid <tenant> --metadata-file idp-metadata.xml`.
3. Verify that no network appliance (WAF, DLP) is modifying the response
   body.

---

#### `decrypt_failed`

**What it means:** The SP could not decrypt the encrypted assertion using
its current private key.

**Likely causes:**
- The IdP encrypted the assertion with an old or wrong SP certificate.
- The SP's signing key was rotated but the IdP still uses the previous
  certificate.

**Resolution:**
1. Verify that the IdP has the SP's current certificate. Re-upload the SP
   metadata to the IdP.
2. If mid-rotation, ensure the prepare step completed and wait for the
   IdP to refresh its cached metadata (see
   [key-rotation.md](key-rotation.md)).

---

#### `assertion_signature_invalid`

**What it means:** The XML signature on the `<Assertion>` element (as
opposed to the outer `<Response>`) failed verification.

**Likely causes:**
- Same as `signature_invalid` — IdP certificate rollover or response
  tampering.

**Resolution:**
- Follow the same steps as for `signature_invalid` above.

---

#### `clock_skew`

**What it means:** The assertion's `NotBefore` / `NotOnOrAfter` timestamps
fall outside the allowed skew window (default: ±120 s).

**Likely causes:**
- The SP server's clock is not synchronized with NTP.
- The IdP's clock is drifting.
- The assertion was delayed in transit beyond the validity window.

**Resolution:**
1. Verify NTP synchronization on the SP host:
   ```bash
   timedatectl status   # systemd
   chronyc tracking     # chrony
   ntpq -p              # ntpd
   ```
2. Check the IdP's clock as well.
3. If legitimate network delays exceed 120 s, consider increasing
   `--clock-skew` (not recommended in production without compensating
   controls).

---

#### `subject_confirmation_mismatch`

**What it means:** The `<SubjectConfirmationData>` does not satisfy the
SP's validation rules — typically `Recipient` does not match the ACS URL,
or `NotOnOrAfter` has passed.

**Likely causes:**
- ACS URL mismatch (similar to `destination_mismatch`).
- Clock skew (similar to `clock_skew`).
- The `InResponseTo` in `SubjectConfirmationData` does not match the
  original request ID.

**Resolution:**
1. Decode the assertion and inspect `<SubjectConfirmationData>`.
2. Verify that `Recipient` matches the SP's ACS URL.
3. Check clock synchronization.

---

#### `algorithm_disallowed`

**What it means:** The SAML response or assertion uses a signature or
digest algorithm that is on the SP's deny list (e.g. RSA-SHA1, SHA1,
DES, MD5).

**Likely causes:**
- The IdP is configured to sign with SHA-1 instead of SHA-256.
- Legacy IdP software that defaults to weak algorithms.

**Resolution:**
1. Reconfigure the IdP to use SHA-256 for both the signature algorithm
   and the digest algorithm.
2. Consult your IdP's documentation for the signing algorithm setting
   (often under "Advanced" or "Security" settings).

---

#### `xxe_detected`

**What it means:** The SAML response XML contains a `<!DOCTYPE>`
declaration or external entity reference. The SP rejects these to prevent
XML External Entity (XXE) attacks.

**Likely causes:**
- A malicious or misconfigured intermediary injected a DOCTYPE.
- A custom IdP implementation incorrectly includes a DOCTYPE preamble.

**Resolution:**
1. Inspect the raw SAML response (base64-decode the `SAMLResponse` form
   parameter) for any `<!DOCTYPE>` declarations.
2. Contact the IdP vendor to remove the DOCTYPE from SAML responses.
3. This is a security control and must not be disabled.

---

#### `signature_wrapping_detected`

**What it means:** The SP detected a signature-wrapping attack — the XML
signature's `Reference` URI does not resolve to the expected `Assertion`
element, or extra signed elements exist outside the asserted scope.

**Likely causes:**
- A genuine attack attempt.
- A non-standard IdP that produces unusual XML structures.

**Resolution:**
1. If this appears in production with a trusted IdP, capture the full
   SAML response (redact sensitive attributes) and contact the IdP
   vendor.
2. Do not disable this check — it prevents a well-known class of SAML
   vulnerabilities.

---

### `not_configured` Bucket (HTTP 404)

---

#### `tid_unknown`

**What it means:** No IdP record exists in the store for the tenant ID
extracted from the request.

**Likely causes:**
- The tenant has not been onboarded for SAML SSO.
- The tenant ID in the login URL (`/saml/login/{tid}`) is misspelled.
- The IdP record was removed or expired.

**Resolution:**
1. Verify the tenant ID: `tikti saml idp show --tid <tenant>`.
2. If no record exists, register the IdP:
   `tikti saml idp register --tid <tenant> --metadata-url <url>`.
3. Check that the login URL uses the correct tenant ID.

---

### `internal` Bucket (HTTP 500)

---

#### `idp_metadata_stale`

**What it means:** The cached IdP metadata could not be used — typically
the signing certificate in the cached metadata has expired or the metadata
itself has exceeded its validity period.

**Likely causes:**
- The IdP's signing certificate expired and the metadata refresher has
  not yet fetched updated metadata.
- The metadata URL is unreachable, preventing automatic refresh.

**Resolution:**
1. Force a metadata refresh:
   `tikti saml idp fetch --tid <tenant>`.
2. If the metadata URL is down, obtain the metadata XML file manually and
   update:
   `tikti saml idp update --tid <tenant> --metadata-file idp-metadata.xml`.
3. Verify the metadata refresher is running and its logs do not show
   persistent fetch errors.

---

#### `internal_error`

**What it means:** An unexpected server-side error occurred during
assertion processing that does not fit any other category.

**Likely causes:**
- Redis connectivity failure during request lookup or replay check.
- A panic recovered by the handler middleware.
- A bug in the assertion validation or token-bridge logic.

**Resolution:**
1. Check the application logs for stack traces or error messages around
   the timestamp of the Error ID.
2. Verify Redis connectivity and health.
3. If the error persists, capture logs and open a support ticket or file
   an issue.

## Quick-Reference Table

| Reason Code | Bucket | HTTP | Most Common Fix |
|---|---|--:|---|
| `request_not_found` | `bad_request` | 400 | User restarts login |
| `destination_mismatch` | `bad_request` | 400 | Fix ACS URL in IdP |
| `missing_attribute` | `bad_request` | 400 | Fix IdP attribute release |
| `request_replay` | `forbidden` | 403 | User restarts login |
| `issuer_mismatch` | `forbidden` | 403 | Re-import IdP metadata |
| `status_not_success` | `forbidden` | 403 | Check IdP sign-in logs |
| `audience_mismatch` | `forbidden` | 403 | Fix entity ID in IdP |
| `signature_invalid` | `forbidden` | 403 | Refresh IdP metadata |
| `decrypt_failed` | `forbidden` | 403 | Re-upload SP metadata to IdP |
| `assertion_signature_invalid` | `forbidden` | 403 | Refresh IdP metadata |
| `clock_skew` | `forbidden` | 403 | Sync NTP on SP and IdP |
| `subject_confirmation_mismatch` | `forbidden` | 403 | Fix ACS URL or sync clocks |
| `algorithm_disallowed` | `forbidden` | 403 | Use SHA-256 in IdP |
| `xxe_detected` | `forbidden` | 403 | Remove DOCTYPE from IdP response |
| `signature_wrapping_detected` | `forbidden` | 403 | Contact IdP vendor |
| `tid_unknown` | `not_configured` | 404 | Register IdP for tenant |
| `idp_metadata_stale` | `internal` | 500 | Force metadata refresh |
| `internal_error` | `internal` | 500 | Check logs, verify Redis |
