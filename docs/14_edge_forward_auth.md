# Edge ForwardAuth

Tikti exposes `GET /v1/auth/forward` for an edge proxy to authenticate a
request before it reaches a DMZ workload. The endpoint supports two credential
types:

- `Authorization: Bearer <token>` is an RS256 access token. The proxy must
  overwrite `X-Tikti-Expected-Audience` with the audience assigned to the
  route. Tikti validates signature, issuer, audience, expiry, user status, and
  token version.
- `Authorization: Bearer <projected-token>` may also be a short-lived
  Kubernetes ServiceAccount token from an explicitly configured workload
  cluster. This credential is accepted only when the route declares a caller
  Service allowlist and the ServiceAccount and `workload-<tenant>` namespace
  match it.
- the configured SAML session cookie, `tikti_idt` by default, is an HS256 ID
  token. Tikti validates signature, issuer, the configured default audience,
  expiry, user status, identity binding, and token version.
- the optional `forwardAuth.accessCookieName` cookie is an RS256 access token.
  It is validated with the same route audience policy as a bearer token. This
  permits same-origin browser API calls without exposing the token to
  JavaScript.

If `X-Tikti-Expected-Tenant` is non-empty, the token `tid` claim must match it.
The proxy may also overwrite `X-Tikti-Allowed-Services` with a comma-separated
service allowlist and `X-Tikti-Required-Scopes` with a space-separated scope
set. Tikti requires an access-token subject to identify an allowed Kubernetes
ServiceAccount (or carry a trusted `service` claim) and requires every declared
scope. A projected ServiceAccount token instead requires a non-empty matching
service allowlist; user scopes neither broaden nor restrict that workload
identity. An empty header leaves that dimension unrestricted for Tikti user or
access tokens, but projected tokens fail closed without an allowlist;
malformed or duplicate policy values fail closed.
The proxy must overwrite or remove all incoming `X-Tikti-*` identity headers
and copy only the following headers from a successful Tikti response:

- `X-Tikti-Subject`
- `X-Tikti-Email`
- `X-Tikti-Tenant`
- `X-Tikti-Role`
- `X-Tikti-Scope`

Success returns `204 No Content`. Missing or invalid authentication and invalid
route policy return `401`; tenant, service, or scope denial returns `403`. Responses are `Cache-Control:
no-store`, and failures never include the supplied credential.

The endpoint enforces the route-level tenant, caller-service, audience, and
scope boundary. The workload must still enforce operation-specific
authorization and resource ownership. Traefik is responsible for setting the expected route policy
and for preventing direct public access to the upstream service.

## Production secret files

Production deployments may mount secrets as files and set
`JWT_SECRET_FILE`, `API_KEY_FILE`, `REDIS_PASSWORD_FILE`, and
`JWKS_PRIVATE_KEY_FILE`. Tikti fails startup when a configured secret file is
missing or empty. This keeps secret values out of Helm values, ConfigMaps, and
container environment variables.
