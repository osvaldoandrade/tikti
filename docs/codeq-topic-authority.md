# CodeQ topic controller authority

The default-off `workloadIdentity.codeqTopicController` configuration authorizes
one installation-owned MASTER controller to reconcile tenant topics without
manually creating a WorkloadBinding for every future tenant. It requires exact
issuer, clusterRef, namespace, serviceAccount and serviceAccountUID fields. The
issuer and cluster must match a configured trusted workload JWT provider. The
verified projected token must also contain a Pod UID. Obtain current identity
and JWKS evidence through the authorized installer; historical UID inventory
alone does not authorize activation.

The existing workload exchange endpoint accepts only the single reserved scope
`codeq:topics:manage` with audience `codeq-producer`. It never falls back to legacy
binding grants. Every exchange reads the retained tenant authority and requires
the exact tenant ID, ACTIVE status, no retirement and a valid creation time.
The token expires in at most sixty seconds and binds the tenant epoch and the
complete controller installation identity. It carries no administrator role.

`GET /v1/internal/codeq/topic-authority` authenticates that token itself, verifies
its signature, issuer, audience, expiry and exact scope, then rereads tenant
state and epoch. It returns only schemaVersion, tenantId, tenantEpoch and active.
The endpoint is no-store and rejects browser cookies/origin, duplicate bearer
headers, query parameters, encoded paths, non-GET methods and request bodies.
It needs no API key and returns no token or tenant display metadata.

CodeQ must independently restrict the scope to topic CRUD and per-topic stats,
and call this authority endpoint at use time. Task and worker APIs must reject
it. Deploy compatible Tikti and CodeQ versions before enabling the canonical
reconciler. Existing legacy account/workload exchanges retain their contracts.

## Installation and rollback

The product chart uses `config.workloadIdentity.codeqTopicController` with the
same field names. Conveste deploys the Infra repository's Tikti chart; that
chart must mirror these values and validation before the installation pin is
updated. Product chart tests alone do not prove installation activation.

Rollback first disables canonical topic reconciliation, then disables this
identity configuration. Existing topic CRs, finalizers and backend data remain
intact. Live introspection immediately denies the disabled configuration;
short token expiry is not the retirement mechanism. Restore a prior reconciler
only with proven exclusive ownership and valid tenant-bound authentication.
Never substitute a static local-tenant administrator credential.
