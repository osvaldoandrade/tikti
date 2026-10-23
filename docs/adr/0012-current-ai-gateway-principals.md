# ADR 0012: Current AI Gateway principals and installation grants

Status: accepted for CFP-116; capability defaults off. Production activation is
an installation decision after cross-repository verification.

## Decision

The `code-llm-service` audience is reserved even when AI is disabled. Its closed
scope set is `code-llm:invoke`, `code-llm:models:read`, and
`code-llm:usage:read`. There is no implicit audience grant for ordinary users.
User exchange intersects the current exact-tenant membership/role permissions
with the enabled tenant client ceiling. Usage requires the current
`code-admin:ai:read` permission. A fixed `scopeCeilingV1` can request this
intersection; it cannot combine with explicit scopes or tenant discovery.

`POST /v1/accounts/token/exchange` keeps the existing server-only ID-token and
API-key boundary. Console uses the API's same-origin `/v1/console/ai-session`
BFF and never receives the ID token or API key. The AI access token is transient.

`POST /v1/workloads/token/exchange` reuses the current projected-token verifier.
The verified issuer, cluster, namespace, service account UID and Pod UID are
bound to the current Service through a signed API identity callback. Workload
tokens use `sub=codefoundry:service:<ServiceUID>`. Optional `userToken` delegation
requires a separately current AI User token in the same tenant; nested
delegation is rejected. The resulting subject is the immutable user ID and the
signed `act` contains the workload identity. Body fields never assign a user.

The callback is `POST /internal/v1/ai-gateway/identity:authorize`, with an empty
body and an RS256 assertion for `code-admin-ai-identity`, subject `tikti`, a
maximum 60-second lifetime and all identity pins in `ai_identity`. The closed
`ai-identity/v1` response resolves the Service UID. Tikti checks the retained
tenant before and after the call and compares every returned identity field.
Timeouts, missing authority and ambiguous JSON fail closed without a cache.

`POST /v1/internal/ai/access-tokens:validate` is private, API-key protected and
takes the principal in the Bearer header with no body/query/browser context. It
returns only 204 on success. Signature, audience, lifetime, current user version,
membership, permissions, client ceiling and current API workload authority are
checked on every validation. AI tokens expire within 300 seconds and never
outlive their source; machine API authority expires within 60 seconds.

`tenant_uid` is the immutable Tenant ID. `tenant_epoch` is the existing retained
tenant lifetime hash of ID plus CreatedAt; it does not change with memberships,
roles, resources, placement or disable/enable. Accounting must preserve quotas
through routine authorization changes and must never reset on an unavailable
authority response.

## Installation machine authority

The additive `aiGrant` selector is mutually exclusive with user delegation,
CodeQ and Logs selectors. It requires exact installation issuer/cluster/
namespace/service account/UID pins and an active runtime tenant:

| Selector | Audience | Exact scopes |
| --- | --- | --- |
| Runtime | code-admin-api | code-admin:ai:runtime |
| CefasRuntime | installation-owned dedicated store | cefas:item:read:ai-usage, cefas:item:write:ai-usage, cefas:query:ai-usage |
| CefasBootstrap | same dedicated store, separate pinned identity | cefas:table:create, cefas:table:describe |

The unchanged Cefas API exposes bootstrap create/describe globally; the separate
bootstrap identity is installation-only and is never the inference runtime.
There is no delete, CDC, arbitrary table or Logs fallback authority. Neither
the Cefas implementation nor existing Logs grants change.

## Migration, rollback and limits

Deploy the compatible API callback and receiver first, with all AI flags off.
Provision explicit tenant roles/client ceilings and installation pins, then
enable `aiGateway.enabled`. The canonical management-scope manifest is version
2026-10-23.1; existing scope boundary rules remain in force. No data migration or
credential rewrite is needed. Disable gateway admission before disabling Tikti
AI or rolling back; preserve ledger reservations and receipts. Existing tokens
will fail current validation when disabled, independently of their expiry.

Current workload authority means verified projected identity plus current
Service/placement authorization, not a new cross-cluster Pod inventory service.
The source-token validity and short issued lifetime bound that observation.
Production must qualify the actual projected-token provider and installation
identity before activation. Local tests do not claim public-path acceptance.

Verification: `make test-ai-gateway`, `make fuzz-ai-gateway`, full race tests,
`go vet ./...`, build and `make helm-test`. Negative cases include disabled
audience bypass, current permission/version withdrawal, nested delegation,
replacement service account UID, mixed selectors and broadened store scopes.
