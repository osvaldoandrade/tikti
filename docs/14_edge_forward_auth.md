# Edge ForwardAuth

Tikti exposes `GET /v1/auth/forward` for an edge proxy to authenticate a
request before it reaches a DMZ workload. The endpoint supports two credential
types:

- `Authorization: Bearer <token>` is an RS256 access token. The proxy must
  overwrite `X-Tikti-Expected-Audience` with the audience assigned to the
  route. Tikti validates signature, issuer, audience, expiry, user status, and
  token version.
- the configured SAML session cookie, `tikti_idt` by default, is an HS256 ID
  token. Tikti validates signature, issuer, the configured default audience,
  expiry, user status, identity binding, and token version.
- the optional `forwardAuth.accessCookieName` cookie is an RS256 access token.
  It is validated with the same route audience policy as a bearer token. This
  permits same-origin browser API calls without exposing the token to
  JavaScript.

If `X-Tikti-Expected-Tenant` is non-empty, the token `tid` claim must match it.
The proxy must overwrite or remove all incoming `X-Tikti-*` identity headers
and copy only the following headers from a successful Tikti response:

- `X-Tikti-Subject`
- `X-Tikti-Email`
- `X-Tikti-Tenant`
- `X-Tikti-Role`
- `X-Tikti-Scope`

Success returns `204 No Content`. Missing or invalid authentication returns
`401`; a tenant mismatch returns `403`. Responses are `Cache-Control:
no-store`, and failures never include the supplied credential.

The endpoint authenticates but does not replace workload authorization. The
workload must still enforce the projected tenant, role, and scope required for
each operation. Traefik is responsible for setting the expected route policy
and for preventing direct public access to the upstream service.

## Production secret files

Production deployments may mount secrets as files and set
`JWT_SECRET_FILE`, `API_KEY_FILE`, `REDIS_PASSWORD_FILE`, and
`JWKS_PRIVATE_KEY_FILE`. Tikti fails startup when a configured secret file is
missing or empty. This keeps secret values out of Helm values, ConfigMaps, and
container environment variables.
