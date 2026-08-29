# ADR 0006: Broker S3 credentials through AWS web identity

## Status

Proposed for CFP-080. T4 entry and independent security review are pending.

## Context

Managed Code Cloud Services already receive a rotating projected Kubernetes
ServiceAccount JWT. Tikti verifies its issuer, JWKS signature, algorithm,
audience, expiry, namespace, ServiceAccount and subject for existing workload
identity flows. The current exchange is intentionally bounded to configured
audiences such as CodeQ and must not be widened into a generic storage grant.

Object Storage needs standard AWS SDKs to obtain temporary MinIO credentials
without copying an access key into a workload namespace. AWS SDK credential
chains understand `AWS_ROLE_ARN` plus `AWS_WEB_IDENTITY_TOKEN_FILE` and call
STS `AssumeRoleWithWebIdentity`; they also support service-specific S3 and STS
endpoints in supported versions.

MinIO supports an STS web-identity operation backed by OIDC and returns
temporary S3 credentials. MinIO, however, does not own Code Cloud tenant,
Service or ResourceBinding intent. Letting it infer authorization directly
from a Kubernetes token, or duplicating grants in Tikti, would create a
confused-deputy and revocation-drift boundary.

## Decision

Tikti will add a default-off AWS Query-compatible
`AssumeRoleWithWebIdentity` broker on a dedicated public STS origin. The edge
may rewrite that unsigned root request to an internal exact handler such as
`POST /v1/storage/sts`; the S3 data path is not rewritten.

The broker uses three distinct identities:

1. The workload's projected Kubernetes JWT authenticates the source Service.
2. A short-lived Tikti service assertion authenticates Tikti to the internal
   code-admin-api authorization endpoint.
3. A short-lived Tikti OIDC assertion, derived only after an allow decision,
   authenticates Tikti to MinIO STS and selects one fixed MinIO policy plus one
   physical bucket.

Tikti does not persist ResourceBindings or MinIO credentials. The Admin API is
the authorization source; MinIO is the temporary-credential issuer.

Tikti also publishes an additive, machine-only OIDC discovery document for the
pinned MinIO integration. It contains the one reviewed issuer, the exact Tikti
JWKS URI, RS256 signing metadata and only claims actually emitted by this
broker. It does not advertise an interactive authorization flow that Tikti does
not implement. The internal discovery/JWKS form and every required field are
locked by the pinned MinIO startup/integration test; existing public JWKS URLs
remain unchanged.

## Public AWS Query contract

The dedicated STS host accepts only a cache-disabled form POST. The internal
handler is not part of the existing JSON workload-exchange API.

Required parameters:

- `Action=AssumeRoleWithWebIdentity`
- `Version=2011-06-15`
- `RoleArn` matching the exact Code Foundry synthetic role grammar
- `RoleSessionName` matching a bounded AWS-compatible token, or a deterministic
  server default when the tested SDK omits it
- `WebIdentityToken` containing the projected Kubernetes JWT

`DurationSeconds`, when present, must equal the single reviewed lifetime for
v1. The initial target is 900 seconds, subject to the pinned MinIO
compatibility test. `Policy`, `PolicyArns.member.*`, `ProviderId`, duplicate
keys, unknown keys, query-string parameters, chunked oversized bodies and
alternate actions/versions are rejected. Inline policy can never narrow or
broaden the platform decision because it is not accepted at all.

Initial parser bounds to verify in implementation:

| Input | Maximum / rule |
| --- | --- |
| request body | 32 KiB |
| WebIdentityToken | 16 KiB, exactly one compact JWT |
| RoleArn | 512 bytes, ASCII exact grammar |
| RoleSessionName | 64 bytes, AWS-compatible safe characters |
| parameter count | 8 |
| request deadline | lower than the edge timeout; one bounded dependency budget each |

The successful response is AWS STS XML with the canonical 2011-06-15
namespace and contains only `AccessKeyId`, `SecretAccessKey`, `SessionToken`,
`Expiration`, assumed-role metadata, subject/provider metadata and a bounded
request ID. Errors use bounded AWS-style XML codes without echoing token,
credential, role path or provider bodies. Every response sets
`Cache-Control: no-store` and `Pragma: no-cache`; redirects and CORS are absent.

## Authentication and role resolution

Tikti reuses the existing projected-token verifier and the configured
`tikti-workload-exchange` audience. It does not accept an ordinary Tikti user
token, SAML cookie, API key, MinIO token or bearer token from another endpoint
as `WebIdentityToken`.

The synthetic role is an SDK selector with this v1 grammar:

```text
arn:aws:iam::<configured-12-digit-id>:role/codefoundry/
  <tenant>/<namespace>/<resource-binding-name>
```

All components are normalized DNS-safe identifiers with length bounds. The
configured account ID prevents a workload from presenting an AWS or another
installation's role. Parsing produces only a lookup key; it never grants
access.

Tikti calls the internal API authorizer with:

- verified issuer, cluster, namespace, ServiceAccount and `sub`;
- synthetic role components;
- requested session lifetime;
- a one-way hash of the presented JWT for audit correlation;
- Tikti request ID.

The call is authenticated by a Tikti-signed RS256 assertion with exact audience
`code-admin-object-storage-authorizer`, exact Tikti service subject, unique
`jti`, at most 60-second lifetime and no tenant-supplied claims. The API
validates it through Tikti JWKS. NetworkPolicy admits this internal endpoint
only from exact Tikti pods. The endpoint is non-cacheable and unavailable to
Console/tenant scopes.

The API allows only when the current ResourceBinding, source Service identity,
placement, ObjectBucket, installation, owner, tenant, namespace, generation,
Ready/Active conditions and rollout cohort all agree. The allow response is a
bounded signed or mutually authenticated response containing:

- physical bucket name;
- `ReadOnly` or `ReadWrite` access class;
- binding UID and generation;
- ObjectBucket UID and observed generation;
- installation ID/region;
- maximum credential lifetime.

It contains no credential or arbitrary policy. Tikti does not cache allow
responses across requests, so a revoked binding denies the next exchange.

## MinIO OIDC assertion and STS exchange

After an allow decision, Tikti creates a short-lived RS256 OIDC JWT with:

- exact Tikti issuer, `aud=minio-sts` and `client_id=minio-sts` where required
  by the pinned MinIO claim-provider contract;
- `sub` derived from the verified Kubernetes identity;
- `tid`, ServiceAccount, binding UID/generation and ObjectBucket UID for audit;
- `preferred_username=<validated physical bucket name>`;
- `policy=code-admin-object-readonly-v1` or
  `code-admin-object-readwrite-v1` selected solely from the allow response;
- unique `jti`, `iat`, `nbf` and bounded `exp` compatible with the pinned
  MinIO minimum lifetime.

No request field can override a claim. Tikti sends the assertion over the
private MinIO Service to MinIO's web-identity STS operation. MinIO fetches
Tikti discovery/JWKS through the exact internal Tikti Service, while the
discovery document and JWT retain one reviewed issuer; no general internet
egress or second issuer is introduced. Tikti does not forward the synthetic
Code Foundry RoleArn or an inline policy. MinIO trusts the exact issuer/
audience/key and expands only the two reviewed fixed policies using the
validated bucket claim.

Tikti parses a size-bounded XML response, verifies that all credential fields
and expiration are present and within the authorized lifetime, and relays a
new bounded AWS-compatible XML response. The assertion and credentials exist
only in request memory and must be zeroed where language/runtime primitives
allow. They never enter Redis, a database, audit detail, log, trace, metric,
panic report or error body.

## Revocation semantics

Binding revocation or target readiness loss denies all new exchanges as soon
as the API commits the state. Credentials already issued by MinIO may remain
valid until their expiration. V1 targets a tested maximum of 900 seconds; it
does not claim instant revocation.

An optional MinIO token-revocation mechanism may be adopted only if the exact
pinned release proves bounded identifiers, idempotency and no shared-policy
impact. Otherwise emergency response disables the STS route/fixed policies
through the reviewed installation rollback. The residual window must receive
explicit independent security and staff/executive acceptance.

## Abuse resistance and privacy

- Rate limit by edge source class and verified workload subject after
  verification; do not use raw token or role ARN as a metric label.
- Bound concurrent MinIO/API calls, body/XML size, timeouts and JWKS refresh.
- Reject redirects for JWKS, API authorization and MinIO STS dependencies.
- Sanitize all incoming identity headers; derive identity only from the token.
- Audit allow/deny with request ID, stable reason, cluster, namespace,
  ServiceAccount and opaque binding/bucket IDs. Keep tenant-sensitive audit
  fields access-controlled and retention-bounded.
- Never log request bodies, form parameters, Authorization, OIDC JWT, MinIO XML
  body or SDK credentials. Logging middleware must explicitly skip/redact the
  handler before it reads a body.
- Stable denial codes do not reveal whether a foreign bucket or binding exists.
- Health endpoints test dependency shape without performing an exchange or
  returning configuration secrets.

## Failure mapping

| Failure | Public result | Retry guidance |
| --- | --- | --- |
| malformed/unsupported AWS Query request | `InvalidParameterValue` / HTTP 400 | fix client configuration |
| invalid/expired projected token | `InvalidIdentityToken` / HTTP 400-compatible STS error | SDK rereads rotated token, then retry |
| binding/tenant/source/target denied | `AccessDenied` / HTTP 403 | do not retry until intent changes |
| API/JWKS/MinIO timeout or unavailable | `IDPCommunicationError` or `ServiceUnavailable` | bounded SDK backoff |
| MinIO response invalid/out of bounds | `InternalFailure` | page; do not return partial credential |
| Tikti overload | `Throttling` / HTTP 429 | jittered backoff and SDK session reuse |

Exact status/code compatibility is locked by consumer tests; error bodies never
include upstream text.

## Observability

Bounded metrics:

- `tikti_storage_sts_requests_total{result,reason}`;
- `tikti_storage_sts_duration_seconds{result}`;
- `tikti_storage_authorizer_duration_seconds{result}`;
- `tikti_storage_minio_sts_duration_seconds{result}`;
- in-flight, throttled, invalid-token and provider-response-invalid gauges/
  counters with closed dimensions.

No tenant, subject, role, binding, bucket, key ID, token hash or request ID is a
metric label. Dashboard and alerts link to the Infra runbook. A synthetic
canary must exercise allow, cross-tenant deny, ReadOnly write deny, refresh and
revocation. One test alert must page the intended on-call path before rollout.

## Compatibility and tests

The endpoint, configuration and routes are additive and disabled by default.
Existing password, SAML, ForwardAuth, JWKS, workload exchange, CodeQ and
workload-account BFF behavior is unchanged.

Required tests include:

- table/fuzz tests for form parsing, duplicate/unknown keys, percent encoding,
  ARN grammar, XML parser, response escaping and size limits;
- projected JWT negative matrix and JWKS rotation/unknown-kid limiter;
- API authorizer authentication, cross-tenant/owner/SA, stale generation,
  inactive binding and ambiguous lookup denial;
- MinIO fake plus pinned-server integration tests for issuer/audience/alg/exp,
  fixed policy/bucket claim, temporary credential lifetime and every allowed/
  denied S3 action;
- sentinel credential tests proving redaction on success, every error and
  cancellation/panic path;
- Go AWS SDK v2, JavaScript v3 and boto3 N-2 starter tests using service-
  specific endpoints, path style, automatic refresh and dependency brownouts;
- 2x peak load, API/JWKS/MinIO slow/unavailable behavior, bounded memory/
  goroutines/connections and no regression to existing Tikti SLOs.

## Rollout and rollback

1. Ship code and configuration with the broker disabled.
2. Enable internal authorization and MinIO OIDC/policies for synthetic identity
   only; keep public route and tenant cohort disabled.
3. Enable the exact STS route for synthetic tests, then the exact S3 route.
4. Complete security, SDK, load/brownout and rollback gates.
5. Roll out with the Object Storage cohort 1/10/50/100 and documented bake
   times.

Rollback first stops cohort/bucket changes, then disables new STS exchange and
waits for the proven credential lifetime (or invokes a reviewed emergency
revocation). It removes public routes and disables the broker/OIDC feature
without deleting bindings, buckets, users, policies or data. It never enables
an API-key/access-key fallback.

## Alternatives rejected

- Extend the generic workload token exchange with bucket/scopes: rejected
  because AWS SDKs would need custom credential code and current audiences
  would be broadened.
- Persist ResourceBinding grants in Tikti: rejected because the Admin API is
  authoritative and duplicate state creates revocation drift.
- Hand the Kubernetes JWT directly to MinIO: rejected because MinIO cannot
  authoritatively resolve Code Cloud Service/ResourceBinding/owner state.
- Return a platform access token and add ForwardAuth to S3: rejected because
  S3 SDKs sign requests with access/secret/session credentials and SigV4.
- Provision static MinIO users per binding: rejected because credentials are
  long-lived and rotation/deletion become cross-cluster secret orchestration.
- Give Tikti the provisioner/root credential: rejected because credential
  brokering does not own bucket lifecycle or policy administration.

## Entry approvals still required

- two-person RFC/ADR review;
- domain-owner approval of ResourceBinding and ObjectBucket invariants;
- independent security approval of parser, trust chain, fixed policies and
  residual revocation window;
- staff/executive service-class and risk sign-off;
- named incident commander and backup;
- a required initial MinIO OIDC activation window because the provider is
  single-replica and configuration restart/reload can interrupt static traffic.

## Primary references

- AWS web identity credential provider:
  <https://docs.aws.amazon.com/sdkref/latest/guide/access-assume-role-web.html>
- AWS service-specific endpoints:
  <https://docs.aws.amazon.com/sdkref/latest/guide/feature-ss-endpoints.html>
- AWS STS operation:
  <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html>
- MinIO web-identity STS:
  <https://docs.min.io/aistor/developers/security-token-service/assumerolewithwebidentity/>
- MinIO OIDC claim policies and policy variables:
  <https://docs.min.io/aistor/administration/iam/access/oidc-access/>
