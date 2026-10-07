# CodeQ binding exchange (ADR-0022 C3)

Tikti issues a short-lived CodeQ token scoped to one tenant and one QueueTopic
to a workload Pod that holds a Publish or Subscribe `ResourceBinding`. The
`ResourceBinding` in code-admin-api is the only grant. Tikti asks the API for
current authority on every exchange. It stores no binding, grant, decision or
issued token for this grant.

The normative contract is platform ADR-0022 (C1 CodeQ claims, C2 API authority,
C3 this exchange). This chapter documents what Tikti implements.

## Flags and configuration

```yaml
workloadIdentity:
  audience: tikti-workload-exchange
  providers: [...]                 # every provider needs a clusterRef when enabled
  scopedWorkloadBindings: false    # R4
  legacyCodeQAdminGrant: true      # R4; absent means true
  codeqBindings:
    enabled: false
    authorityUrl: http://<svc>.<ns>.svc.cluster.local:<port>/internal/v1/codeq-bindings:authorize
    serviceSubject: tikti:codeq-binding-exchange
    accessTokenTtlSeconds: 300     # 30..300
    dependencyTimeoutSeconds: 2    # 1..10
    maximumConcurrent: 8           # 1..32
    perIdentityPerMinute: 6        # 1..60
```

The checks below run at startup. Startup never calls `authorityUrl`.

- **Always:** no issuer and no non-empty clusterRef may repeat across trusted
  providers. This includes the legacy single issuer. Storage STS, forward-auth
  and every workload exchange share one issuer -> clusterRef map, so a
  duplicate would let one provider silently replace another.
- **When `codeqBindings.enabled`:** startup is refused unless all of these hold:
  - every trusted provider has a clusterRef;
  - `authorityUrl` is exactly one of the two forms above, either in-cluster
    HTTP with an explicit port or HTTPS, with the exact path and no
    credentials, query or fragment;
  - `serviceSubject` is `tikti:codeq-binding-exchange`;
  - the TTL, timeout, concurrency and rate are within the bounds above;
  - the subject audience is `tikti-workload-exchange`;
  - `issuerBaseUrl` is one exact HTTPS origin.

## Request

The grant uses the existing `POST /v1/workloads/token/exchange`. A non-empty
`codeqTopicId` selects it before the topic-manage, Trino and legacy branches,
so such a request never reaches a legacy grant. The decoder rejects unknown
fields. A body that names `clusterRef`, `namespace`, a ServiceAccount or a UID
is therefore refused with 400.

```json
{"subjectToken":"<content of TIKTI_WORKLOAD_TOKEN_FILE>",
 "subjectTokenType":"urn:ietf:params:oauth:token-type:jwt",
 "audience":"codeq-producer",
 "scopes":["codeq:publish"],
 "tenantId":"conveste","codeqTopicId":"conveste.cflow-executar"}
```

The policy comes only from the audience and the exact scope set. Order does not
matter, but duplicates or extra scopes are refused.

| Audience | Scopes | Policy |
|---|---|---|
| `codeq-producer` | `codeq:publish` | Publish |
| `codeq-worker` | `codeq:abandon codeq:claim codeq:heartbeat codeq:nack codeq:result` | Subscribe |

## Procedure and refusal codes

The first failure decides. Every refusal body is
`{"error": "<legacy text>", "code": "<code>", "correlationId": "<uuid>"}`.
The correlation ID is also the `requestId` sent to the authority.

| Step | Condition | Status | `code` |
|---|---|---|---|
| dispatch | combined with `codeq:topics:manage` or a `trino:` audience | 400 | `InvalidRequest` |
| 1 | `codeqBindings.enabled` is false | 403 | `FeatureDisabled` |
| 2 | audience/scope set, tenant, `codeqTopicId == tenantId + "." + <DNS label <= 63>`, token type | 400 | `InvalidRequest` |
| 3 | projected token invalid, or its identity claims disagree | 401 | `SubjectTokenInvalid` |
| 3 | no ServiceAccount UID or Pod UID (unbound token) | 401 | `UnboundSubjectToken` |
| 3 | issuer has no clusterRef | 403 | `IssuerAmbiguous` |
| 4 | tenant missing, not Active, retired or not yet created | 403 | `TenantInactive` |
| 5 | more than `perIdentityPerMinute` attempts per (clusterRef, namespace, ServiceAccount, Pod UID) | 429 + `Retry-After` | `RateLimited` |
| 5 | `maximumConcurrent` authority calls already in flight | 503 + `Retry-After: 1` | `AuthorityBusy` |
| 6 | authority answered 429 or 503 | 503 + `Retry-After: 1` | `AuthorityUnavailable` |
| 6 | authority transport error, timeout, other non-200 (including 401/403), or non-conforming response | 503 | `AuthorityUnavailable` |
| 7 | authority `allowed:false` | 403 | `Authority<Reason>`, for example `AuthorityPlacementMismatch` |
| 8 | no eligible binding for the topic and policy | 403 | `BindingNotFound` |
| 8 | more than one eligible binding | 403 | `BindingAmbiguous` |
| 9 | `min(accessTokenTtlSeconds, subject lifetime) < 30 s` | 401 | `SubjectTokenExpiring` |
| 3, 4, 9 | JWKS, tenant store or signing key unavailable | 503 | `IdentityUnavailable` |

The clusterRef comes only from the trusted issuer -> clusterRef map. Namespace,
ServiceAccount name, ServiceAccount UID and Pod UID come only from the verified
projected token. Both UIDs must be canonical lowercase UUIDs.

The tenant check reads the tenant store directly. It uses the same lifetime
predicate as the topic-controller authority (`activeTenant`) and does not
depend on the topic controller being configured.

## Authority call (C2)

- The request is `POST authorityUrl` with
  `Authorization: Bearer <service assertion>`.
- The service assertion carries `iss` (the Tikti issuer),
  `aud=code-admin-codeq-binding-authority`, `sub=tikti:codeq-binding-exchange`,
  `jti`, `iat`, `nbf=iat-5` and `exp=iat+60`. It has no `tid`, `scope` or
  `eventTypes`.
- The body is `{schemaVersion, requestId, tenantId, clusterRef, namespace,
  serviceAccountName, serviceAccountUid, podUid}` with
  `schemaVersion=codeq-binding-authority/v1`.
- The call follows no redirects and makes no retries. It is bounded by
  `dependencyTimeoutSeconds`.
- The response must meet all of these, or the exchange fails with
  `AuthorityUnavailable`:
  - status 200, `Content-Type: application/json`, `Cache-Control: no-store`
    and `Pragma: no-cache`;
  - at most 64 KiB and exactly one JSON object with no unknown fields;
  - `schemaVersion` and an echoed `requestId`.
- `allowed:true` requires `reason=Resolved`. It may carry at most 32
  `bindings`. Each binding must have a valid `bindingUid`, `generation >= 1`,
  a DNS-label `topicName`, `topicId == tenantId + "." + topicName` and a policy
  of Publish or Subscribe. `allowed:true` with no bindings is valid; Tikti then
  answers `BindingNotFound`.
- `allowed:false` requires a closed reason and empty `bindings` and
  `excluded`. The closed reasons are `NamespaceNotBound`, `ServiceNotFound`,
  `ServiceAmbiguous`, `ServiceNotReady`, `PlacementMismatch`,
  `PlacementAmbiguous` and `TooManyBindings`.
- `excluded` items are validated for shape and reason but never grant
  anything. The closed exclusion reasons are `TargetKindUnsupported`,
  `QueueBindingConflict`, `PolicyInvalid`, `OwnerMismatch`,
  `BindingNotReady`, `TopicNotFound`, `TopicTenantMismatch`,
  `TopicNotReady` and `TopicIdentityMismatch`. Both closed sets are exactly
  the code-admin-api vocabularies; an unknown reason fails the whole decision
  closed.
- `QueueBindingConflict` excludes every QueueTopic binding of a Service except
  the one whose name sorts first. The primary binding is still issued; a
  request for an excluded topic is `403 BindingNotFound`, and the audit line
  records `exclusionReason`.

Tikti does not cache the decision, memoize it or cache negative results.

## Issued token

The issued token has exactly these claims, signed RS256 with the Tikti `kid`:

| Claim | Value |
|---|---|
| `iss` | the workload issuer, the same one as legacy workload tokens |
| `aud` | `codeq-producer` or `codeq-worker`, as a single string |
| `sub` | `codefoundry:workload:<clusterRef>:<namespace>:<serviceAccount>:<podUid>` |
| `tid` | the tenant |
| `scope` | `codeq:publish`, or `codeq:abandon codeq:claim codeq:heartbeat codeq:nack codeq:result` |
| `eventTypes` | `[<topicName>]` |
| `codeq_binding` | `{uid, generation, policy, topicId}` |
| `cluster_ref` | the trusted clusterRef |
| `iat`, `exp` | `exp - iat = min(accessTokenTtlSeconds, remaining subject lifetime) <= 300` |
| `jti` | a UUID |

The token never carries `role`, `email`, `tenant_epoch`, `topic_controller`
or `nbf`. The response keeps the `WorkloadTokenExchangeResp` shape with
`eventTypes: [<topicName>]` and `Cache-Control: no-store`.

## Audit and metrics

One line is written per decision:

```
audit event=codeq_binding_exchange decision=allow|deny code=... correlationId=...
  tenantId=... clusterRef=... namespace=... serviceAccount=... serviceAccountUid=...
  podUid=... topicId=... policy=... bindingUid=... bindingGeneration=...
  authorityLatencyMs=... authorityResult=... authorityStatus=... exclusionReason=...
  [jti=... exp=... on allow only]
```

`authorityResult` is the closed authority call result (below) and
`authorityStatus` the HTTP status (0 when no response arrived). The authority
response body is never logged.

| `authorityResult` | Meaning | Operator action |
|---|---|---|
| `allowed` / `denied` | conforming 200 decision | none |
| `throttled` | authority answered 429 or 503 (busy, store unavailable, deadline) | outage or load; the workload retries after 1 s |
| `rejected` | authority answered 401 or 403 to the Tikti service assertion | misconfiguration: Tikti issuer/kid, `code-admin-codeq-binding-authority` audience or `IDENTITY_AUDIENCES`; retrying does not help |
| `invalid` | 200 response that does not match C2 (including an unknown reason) | contract drift between Tikti and code-admin-api |
| `unavailable` | transport error, timeout, local refusal or any other status | network or API outage |

The line never contains the subject token, the access token, the service
assertion, any hash of them, or the `Authorization` header.

| Metric | Labels |
|---|---|
| `tikti_codeq_binding_exchange_total` | `result` (issued/denied/error), `code`, `policy`, `cluster_ref` |
| `tikti_codeq_binding_authority_seconds` | `result` (allowed/denied/throttled/rejected/invalid/unavailable) |
| `tikti_codeq_binding_authority_in_flight` | none |
| `tikti_workload_legacy_unscoped_binding_total` | none |
| `tikti_workload_legacy_codeq_admin_exchange_total` | `cluster_ref`, `namespace` |

Pod UIDs, binding UIDs and tokens are never used as labels.

The rate limit is per process. With N replicas the effective limit is
N x `perIdentityPerMinute`. Conveste runs one replica.

## Cluster-scoped WorkloadBinding records (legacy path)

`WorkloadBinding`, its upsert request and its revoke request accept optional
`clusterRef` and `serviceAccountUid`.

- When either field is set, the legacy exchange matches it against the verified
  subject.
- A record with a clusterRef is stored under `clusterRef + NUL + subject`.
- The record scoped to the verified clusterRef wins. An unscoped record is read
  only when no scoped record exists, and each such read increments
  `tikti_workload_legacy_unscoped_binding_total`.
- With `scopedWorkloadBindings: true` and more than one trusted provider,
  upserts must carry a trusted clusterRef and unscoped records stop being
  authority.
- With `legacyCodeQAdminGrant: false`, legacy `codeq:admin` workload exchanges
  are refused.
- `tikti-bootstrap` writes a scoped record whenever
  `TIKTI_BOOTSTRAP_TRUSTED_CLUSTER_REFS` lists more than one clusterRef. It
  then requires `TIKTI_BOOTSTRAP_WORKLOAD_CLUSTER_REF` to name one of them;
  `TIKTI_BOOTSTRAP_WORKLOAD_SERVICE_ACCOUNT_UID` is optional.

## Revocation and rollback

Every exchange is decided live, so the next exchange is denied immediately
after any of these:

- the binding is deleted or becomes unready;
- the Service is misplaced;
- the tenant becomes inactive.

Tokens already issued stay valid for at most 300 s, plus CodeQ's skew bound.

To roll back, set `codeqBindings.enabled: false`. New exchanges then get
`FeatureDisabled`, and issued tokens expire within 300 s. To disable the API
side, turn off `codeq.bindingAuthority.enabled`; Tikti then fails closed with
`AuthorityUnavailable`. Never fall back to static CodeQ tokens.
