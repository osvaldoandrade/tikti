# ADR 0004: Correlate SAML state cookies with `InResponseTo`

## Status

Accepted.

## Context

Production validation after the host-bound cookie migration showed a valid new
AuthnRequest remaining in Kvrocks while ACS rejected the callback with
`request_not_found`. The browser sent a state cookie, so missing-cookie recovery
did not run, but the first same-name cookie selected by `net/http` did not
identify the request referenced by the Google Workspace response.

Interrupted flows, browser cookie retention, and migrations can leave more than
one same-name cookie in the request header. Selecting the first cookie is not a
safe correlation rule.

## Decision

For a structurally parseable SAML Response, Tikti reads its `InResponseTo` and
selects the exact `__Host-tikti_saml_state` cookie whose value matches that
request ID. The comparison is constant-time. Tikti still requires the browser
cookie and still atomically consumes the corresponding pending request before
the existing signature, issuer, destination, audience, time, and assertion
validation pipeline.

`InResponseTo` is used only to select among browser-bound state cookies. It does
not establish identity or trust. A malformed response follows the historical
cookie-selection path and is rejected by the validation pipeline.

The selected state cookie is deleted before the consume attempt so expired or
already-consumed state cannot poison the next login.

## Consequences

- Stale same-name cookies cannot shadow the state for the current response.
- Missing-cookie same-origin repost remains unchanged.
- Browser binding, one-time Kvrocks consumption, and cryptographic validation
  remain mandatory.
- Parallel logins can coexist because each response selects its own request ID.

