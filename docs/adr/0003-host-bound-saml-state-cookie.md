# ADR-0003: Use a host-bound SAML state cookie

**Status:** Accepted

**Date:** 2026-07-29

## Context

After Tikti `v0.2.63` reached production, an SP-initiated Google Workspace
login still failed with `request_not_found`. Per-pod metrics showed one
`tikti_saml_authn_requests_total` increment and no
`tikti_saml_state_cookie_recovery_total` increment. The new request key
remained in Kvrocks after the ACS rejection, and an isolated production
diagnostic proved the same atomic `GET` and `DEL` script worked.

Those observations establish that the ACS received a state cookie that did not
identify the current pending request. The browser had a stale or duplicate
`tikti_saml_state` cookie from the prior production attempts.

## Decision

Tikti uses `__Host-tikti_saml_state` for new SAML request correlation. The
cookie is `Secure`, `HttpOnly`, `SameSite=None`, host-only, and uses `Path=/`,
which are the browser-enforced requirements of the `__Host-` prefix.

The old cookie name is no longer read. A stale legacy cookie can coexist in the
browser but cannot shadow the new cookie or influence request correlation.
The same-origin repost from ADR-0002 remains available when browser privacy
controls omit the new cookie on the cross-site IdP POST.

## Security properties

- No `Domain` attribute can be attached to the cookie.
- A sibling domain cannot create a valid colliding `__Host-` cookie.
- Tikti still consumes a pending request before assertion validation.
- `InResponseTo`, issuer, audience, destination, signatures, replay checks,
  tenant selection, and role mapping are unchanged.

## Alternatives considered

### Iterate over every cookie with the legacy name

Rejected because a Domain cookie injected by a sibling host could be selected
if it happened to correlate with an attacker-controlled pending request.

### Delete the legacy cookie

Rejected as the sole fix because Tikti cannot reliably expire every historical
combination of host-only and Domain cookie scope.

### Remove browser-state correlation

Rejected because it would weaken the login-CSRF boundary.

## Rollback

Restore Tikti `v0.2.63`. Existing tenant IdP configuration and Kvrocks data do
not change. Browsers may again encounter the stale-cookie collision until the
legacy cookie expires.
