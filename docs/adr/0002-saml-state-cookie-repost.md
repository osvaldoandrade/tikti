# ADR-0002: Recover the SAML state cookie through a same-origin repost

**Status:** Accepted

**Date:** 2026-07-29

## Decision request

Identity Platform will ship same-origin ACS repost recovery by
2026-07-29 17:00 UTC. Production SAML login targets one accepted response per
SP-initiated test from a baseline of zero accepted responses across two tests
on 2026-07-29, at the cost of one extra browser POST only when the cross-site
IdP POST omits the state cookie. Cloud Logging query
`httpRequest.requestUrl:"/saml/"` in project `code-company-admin-prod`
reproduces the baseline.

## Context

Google Workspace returned valid SAML responses to the production ACS endpoint,
but Chrome omitted `tikti_saml_state` from the cross-site form POST. Tikti
rejected both attempts with `request_not_found` before reading tenant trust or
validating the assertion. The state cookie uses `SameSite=None; Secure` as
required by the HTTP-POST binding, but browser privacy controls may still
withhold it.

Tikti must keep the browser-bound state cookie requirement. Falling back to an
untrusted `RelayState` or `InResponseTo` value would allow login-CSRF: an
attacker could submit the attacker's valid SAML response in a victim's browser
and bind the victim to the attacker's session.

## Decision

When the first ACS POST lacks `tikti_saml_state`, Tikti returns a
cache-disabled HTML page that reposts the same `SAMLResponse` and `RelayState`
to `/saml/acs` from the Code Foundry origin. The browser then attaches the
existing first-party state cookie. Tikti marks the repost and rejects a second
missing-cookie attempt, which prevents loops and preserves fail-closed
behavior.

The page uses `html/template`, a per-response CSP nonce, `form-action 'self'`,
`frame-ancestors 'none'`, and `Cache-Control: no-store`. Tikti does not log the
SAML response, assertion, RelayState, cookie, or repost page body. Existing
signature, issuer, audience, destination, replay, tenant, and request
correlation checks remain unchanged.

## Reversibility

Identity Platform will restore the Tikti `v0.2.62` image within 10 minutes if
the production ACS error rate increases or the synthetic SAML login does not
complete. The IdP configuration remains stored in Kvrocks and does not require
rollback.

## Consequences

- Browsers that send the state cookie continue through the existing one-POST
  path.
- Browsers that withhold the cookie execute one additional same-origin POST.
- Browsers that do not store or return the state cookie still receive
  `request_not_found`; Tikti never substitutes assertion data for browser
  state.
- Operators can count recovery attempts, successes, and failures through
  `tikti_saml_state_cookie_recovery_total`.

## Alternatives considered

### Trust `RelayState` or `InResponseTo` when the cookie is absent

Rejected because those values correlate the response with a request but do not
bind the login to the browser that initiated it.

### Change the state cookie to `SameSite=Lax`

Rejected because Lax cookies are not attached to a cross-site top-level POST.
The login would fail before assertion validation in every conforming browser.

### Disable the state-cookie check

Rejected because it removes the login-CSRF control documented in the SAML
threat model and external penetration-test report.

## References

- `docs/12_saml_federation_hld.md`
- `docs/security/saml-threat-model.md`
- `docs/security/saml-pentest-report.md`
- `docs/threat-models/0002-saml-state-cookie-recovery.md`
- `docs/runbooks/tikti/saml-state-cookie-recovery.md`
