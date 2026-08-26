# Workload identity exchange

Tikti exchanges a projected Kubernetes ServiceAccount JWT for a short-lived,
tenant-bound provider token. This route does not use the Tikti API key because
the projected JWT is the client credential.

## Runtime configuration

```yaml
workloadIdentity:
  audience: tikti-workload-exchange
  providers:
    - clusterRef: code-cloud-acceptance
      issuer: https://kubernetes-master.example.com
      jwksUrl: https://container.googleapis.com/v1/projects/example/locations/us-central1-a/clusters/code-cloud-acceptance/jwks
      authentication: gcp
    - clusterRef: itransform-cluster
      issuer: https://kubernetes-workload.example.com
      jwksUrl: https://gke-example.us-central1-a.gke.goog/openid/v1/jwks
      authentication: gcp
  httpTimeoutSeconds: 5
  jwksCacheTtlSeconds: 300
  accessTokenTtlSeconds: 300
```

Each provider's issuer and JWKS URL must be configured together, and issuers
and cluster references must be unique. The legacy top-level `issuer`, `jwksUrl`,
and `jwksBearerTokenFile` fields remain supported for one cluster. The JWKS URL requires
HTTPS outside loopback tests. Tikti accepts only RS256, an exact issuer and
single audience, a non-expired token, an RSA key of at least 2048 bits, and
matching Kubernetes namespace, ServiceAccount, and `sub` claims. JWKS
redirects are rejected, responses are capped at 1 MiB, and unknown `kid`
refreshes are rate-limited to protect the issuer.

`authentication: gcp` obtains an Application Default Credentials access token
and is accepted only for the GKE REST `https://container.googleapis.com/.../jwks`
resource or an exact `https://*.gke.goog/openid/v1/jwks` DNS endpoint. The Tikti
Google ServiceAccount therefore needs read-only cluster access in every trusted
GKE project; DNS endpoints also require a Kubernetes authorization grant for
the non-resource JWKS path. Non-GKE and on-premises clusters use
`authentication: none` with a reachable HTTPS JWKS endpoint, or the existing
bounded bearer-token-file option.

Environment variables with the `WORKLOAD_IDENTITY_` prefix override these
values. `WORKLOAD_IDENTITY_ACCESS_TOKEN_TTL_SECONDS` must be from 1 through
3600.

## Direct API Gateway authentication

A managed Code Cloud workload receives the same short-lived projected token at
`$TIKTI_WORKLOAD_TOKEN_FILE`. It may send that token directly as a Bearer
credential to a public or internal API Gateway route. Tikti accepts it only
when the route has an explicit `allowedServiceRefs` entry matching the token's
ServiceAccount and the `workload-<tenant>` namespace matches the route tenant.
No workload binding is required for this flow: the route allowlist is the
authorization boundary. User scopes still apply to user/access tokens; they do
not replace or broaden the workload caller allowlist.

## Bounded workload-account broker

An application BFF that needs password signup/signin without holding a Tikti
API key can be declared under `workloadAccountBFF.clients`. The feature is off
by default and requires workload-identity verification plus tenant-scoped
tokens, exact membership reads and membership-v2 writes for every declared
tenant.

```yaml
workloadAccountBFF:
  enabled: true
  clients:
    - tenantId: bereia
      namespace: workload-bereia
      serviceAccount: bereia-api
      audience: bereia-api
      role: bereia-user
      scopes: [bereia-api:read, bereia-api:write]
      ttlSeconds: 900
```

The namespace must be exactly `workload-<tenantId>` and the audience must be
exactly the ServiceAccount name. Each projected subject may appear once. Roles
cannot be a platform-admin role, scopes must be sorted unique values prefixed
by the audience, and TTL is bounded from 60 through 3600 seconds. At startup,
configuration validation fails closed on any mismatch.

The bootstrap job idempotently ensures the exact tenant role and one
service-type, token-exchange-only audience marked as Tikti-managed. A
pre-existing role or audience with different ownership or grants is a hard
conflict; bootstrap does not broaden it.

`POST /v1/workloads/accounts/register` and
`POST /v1/workloads/accounts/session` authenticate the projected token first
and select configuration exclusively by its verified Kubernetes subject. The
request contains only end-user email and password. It cannot choose tenant,
role, audience, scopes or TTL. Registration creates an active password user
and exactly one configured membership, with safe idempotent replay. Session
requires that exact membership before issuing a tenant-scoped RS256 token.
The exact `/identity/v1/workloads/accounts/register` and
`/identity/v1/workloads/accounts/session` production-edge aliases are handled
by the same controllers; no wildcard identity prefix or additional HTTP method
is registered.

The BFF must reread its projected token file for each request so normal
Kubernetes rotation takes effect. It must never log either credential, persist
the returned access token in application storage, expose it to browser
JavaScript, or fall back to an administrative API key.

## Register a binding

Binding management requires the Tikti API key in `X-API-Key`. Workload identity
cannot start with an empty administration key, invalid signing key, or signing
key below 2048 bits. The example value is a placeholder, not a real credential.

```http
POST /v1/workloads/bindings
X-API-Key: REDACTED
Content-Type: application/json
```

```json
{
  "subject": "system:serviceaccount:code-admin:code-admin-controller-queue",
  "namespace": "code-admin",
  "serviceAccount": "code-admin-controller-queue",
  "grants": [
    {
      "tenantId": "payments",
      "audience": "codeq-producer",
      "scopes": ["codeq:admin"]
    }
  ]
}
```

The subject, namespace, and ServiceAccount must agree exactly. Duplicate tenant
grants, unknown audiences, additional scopes, and malformed tenant identifiers
are rejected.

## Exchange contract

```http
POST /v1/workloads/token/exchange
Content-Type: application/json
```

```json
{
  "subjectToken": "PROJECTED_JWT",
  "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
  "audience": "codeq-producer",
  "scopes": ["codeq:admin"],
  "tenantId": "payments"
}
```

The response echoes the tenant, audience, scopes, token type, and lifetime so a
controller can fail closed on any mismatch. Responses use `Cache-Control:
no-store`.

- `400`: malformed target request or unsupported audience.
- `401`: invalid projected JWT.
- `403`: missing, revoked, cross-tenant, or scope-mismatched binding.
- `503`: JWKS, Redis, or signing service unavailable.

## Revocation

```http
POST /v1/workloads/bindings/revoke
X-API-Key: REDACTED
Content-Type: application/json

{"subject":"system:serviceaccount:code-admin:code-admin-controller-queue"}
```

Once revocation is committed to Redis, subsequent exchanges are denied.
Already issued access tokens, including a request already in flight when the
revocation commits, expire within the configured TTL.

## TLS, key rotation, and audit

- Expose Tikti and the Kubernetes JWKS endpoint through trusted TLS.
- Publish the new Kubernetes signing key before issuing tokens with its `kid`.
- Keep the previous key published until every projected token it signed has
  expired.
- Audit binding create/update/revoke and exchange allow/deny using subject,
  namespace, ServiceAccount, tenant, audience, scopes, result, and request ID.
- Never record the projected JWT, issued access token, private key, or API key.

## Rollout

1. Configure issuer/JWKS in a non-production Tikti deployment.
2. Register one controller ServiceAccount and one synthetic tenant.
3. Prove valid exchange plus wrong issuer, audience, namespace, subject,
   tenant, scope, expiry, and revocation cases.
4. Verify CodeQ accepts the RS256 token through Tikti JWKS.
5. Observe exchange latency and denial rate before adding tenants.

Abort on any cross-tenant success, token leakage, signature bypass, or exchange
after binding revocation.

For an account broker client, additionally prove valid registration replay and
session, then wrong issuer, audience, namespace, ServiceAccount, subject,
tenant membership, password, request shape and HTTP origin through the BFF.
Keep the broker disabled until its role and managed audience bootstrap without
conflict.

## Rollback

Revoke the binding first, stop the controller, and restore the prior compatible
Tikti image. Do not introduce a static token fallback. Preserve only metadata
needed to investigate the failed exchange.

For the account broker, disable signup/signin at the application BFF first,
then disable the exact broker client and restore the prior compatible Tikti
image. Do not delete users or memberships during rollback; preserving them
avoids destructive identity rollback and makes a later corrected release
idempotent.
