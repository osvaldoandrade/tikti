# ADR 0010: Administrative Tikti account deletion

Status: accepted for implementation, 2026-10-16. Owner request: provide separate,
simple tenant-access removal and global Tikti account deletion. Architecture,
contract, migration and security review are recorded in the coordination plan.

## Context

Removing a USER access assignment affects one tenant. It does not delete the
account or remove inherited group access. Legacy self-deletion is credential
and email based and cannot safely administer another immutable subject,
especially where a tenant-local SAML principal shares a global account's email.

## Decision

Tikti owns the additive `DELETE /v1/admin/identity/directory/users/{userId}`
operation. Require the private service key and current provenance-bound platform
administrator bearer. Deny self-deletion. The caller supplies the positive
`DirectoryUser.version` as an exact quoted `If-Match`; this is stored user
`Revision + 1`, so the initial internal zero has a usable public version.
No body, query, wildcard condition, preview resource or new dependency is added.

Redis WATCH/MULTI checks actor and target in one transaction. The actor must
remain ACTIVE ADMIN at the exact server-validated tokenVersion and Revision;
SAML platform allowlist validation remains in the token service. A recovered
password MASTER administrator also requires the exact direct MASTER ADMIN
assignment and reverse index. There is no all-administrator deletion ban or
request-time global administrator count. Concurrent administrators cannot delete
one another successfully because each transaction watches both user hashes.

Deletion removes only the target's canonical password/global or federated user,
owned email/order/SAML aliases, USER assignments, group memberships and legacy/V2
memberships. Affected groups gain a version. Reverse sets are bounded before
materialization: 500 entries per set and 500 total relationship references;
transactions retry at most eight times. Malformed/ambiguous canonical records,
foreign-owned canonical aliases and inconsistent reverse links fail closed.
Tenant/group definitions, other subjects, workload data and audit history remain.
Exact UID reads resolve either canonical hash without email linking. The global
directory collection continues to list the existing indexed global identities;
this change does not add a federated-global discovery scan or migration.

Access and identity tokens resolve current authority by immutable UID, so a
removed UID cannot authenticate a replacement account sharing its email.
Email sign-in and password-reset codes are bound to the original UID and
TokenVersion in their existing 900-second payload. Consumption returns that
proof and resolves only UID. Unbound codes issued before this release are
rejected and must be requested again. Reset writes retain the existing Revision
CAS. No OOB scan, additional store or permanent deletion tombstone is needed.

## Consequences and alternatives

Deletion is irreversible through this API; binary rollback cannot restore an
account. A repeated authorized deletion of an absent UID returns 204. A changed
present user returns 412 and requires a new review; no automatic overwrite is
allowed. The external SAML IdP account is unaffected: a subsequent valid SSO can
create a new UID unless access is also removed at the IdP. Disabling an account,
deleting by email, a client-side fake removal, global scans and manual Redis
cleanup were rejected because they do not satisfy the subject/ownership contract.

## Rollout and rollback

No backfill or storage rewrite. The existing completed-backfill marker is
required inside the deletion transaction; legacy import is permanently disabled
once that marker exists. Publish separate guard-only and feature source TAGs.
Deploy the guard-only Tikti image and retain it as the minimum rollback baseline,
then deploy feature Tikti, then the audited API proxy, then
Console using immutable release images. Previous clients ignore the additive
version and keep existing operations. New Console offers deletion only with a
positive version. Retain previous component images. Roll back only these changed
components; disable the new action first. Do not use production-user deletion as
a rollout test. After the first real account deletion, never roll Tikti back
below the retained guard: older binaries can import historical legacy users and
accept email-bound OOB credentials even if administrative DELETE is disabled.
See `docs/runbooks/tikti/administrative-user-deletion.md`.
