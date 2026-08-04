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
      jwksUrl: https://container.googleapis.com/v1/projects/example/locations/us-central1-a/clusters/itransform-cluster/jwks
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
and is accepted only for `https://container.googleapis.com/...` JWKS URLs. The
Tikti Google ServiceAccount therefore needs read-only `container.clusters.get`
access in every trusted GKE project. Non-GKE and on-premises clusters use
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

## Rollback

Revoke the binding first, stop the controller, and restore the prior compatible
Tikti image. Do not introduce a static token fallback. Preserve only metadata
needed to investigate the failed exchange.
