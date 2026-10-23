# AI Gateway identity threats

Protected assets are tenant attribution, user/workload authority and the
dedicated accounting store. No provider credential enters Tikti's AI protocol.

| Threat | Control and evidence |
| --- | --- |
| Legacy audience bypass while disabled | Reserved aliases enter the closed AI branch; default-off regression test. |
| Forged tenant/user/actor | Current exact membership; signed subject and act; API resolves Service UID from verified workload pins. |
| Stale user privileges | Current token version, active user, password-change state, membership, role and client ceiling checked at validation. |
| Nested or broader delegation | AI User source only, same tenant lifetime, requested scopes subset and minimum source expiry. |
| Workload gains installation privileges | Separate aiGrant selector, exact immutable installation pins, no Logs/CodeQ selector mixture. |
| Runtime creates/deletes arbitrary tables | Table-scoped runtime read/write/query; separate bootstrap identity; no runtime create/describe/delete/CDC. |
| Callback substitution/ambiguity | Fixed origin/path, no redirects/proxy/retries, bounded typed JSON, exact returned identity comparison. |
| Dependency outage renews authority | Unavailable response returns no token; no previous-authority cache. |
| Token/secret disclosure | Empty-body private validator, status-only output, BFF cookie boundary; errors never include raw tokens or callback bodies. |

The API and Tikti remain trusted authorization owners. Installation pins and
signing keys are not tenant-editable. A stolen valid token remains a bearer
capability until current authority is withdrawn or its short lifetime expires.
This feature does not redesign signing-key custody or the existing projected
token verifier. MASTER credential grants remain API policy, not Tikti tenant
membership or a generic cross-tenant SecretGrant.
