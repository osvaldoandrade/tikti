# Identity directory V2 migration and rollback

Identity V2 replaces the former sign-up and membership administration HTTP
surfaces. There are no compatibility aliases: callers must use the directory,
group, and explicit-tenant access-assignment routes under
`/v1/admin/identity`. Existing authentication, SAML, role, and client data is
not deleted by the cutover.

## Startup migration

Before HTTP traffic is served, Tikti runs a bounded Redis migration. It indexes
safe user lookup fields and projects every valid legacy membership as a direct
user assignment. The migration:

- normalizes email ownership and rejects ambiguous duplicates;
- prefers the guarded V2 membership projection when legacy and V2 copies
  differ;
- treats an already-created directory assignment as authoritative, so a replay
  cannot undo a later administrator edit;
- writes a completion marker only after users and assignments finish; and
- resumes safely after interruption, then treats the completion marker as the
  cutover boundary so a later direct-access revocation is never resurrected
  from a stale legacy membership.

The legacy hashes remain read-only migration input. New administration writes
only the Identity V2 assignment model. Directory responses never project
password hashes, temporary passwords, token versions, or SAML external
subjects.

## Groups rollout

`identityGroupsV1` and `IDENTITY_GROUPS_V1` control native group mutations and
default to false. Enable the flag only after the startup backfill succeeds on
the release image. Groups are global and non-nested; assignments always name an
exact tenant. SAML `groups` claims are not imported into this model.

## Rollback

Disable `identityGroupsV1` to stop group create, update, member, delete, and
group-assignment mutations. Reads, direct assignments, and already stored group
data remain intact. Do not delete V2 Redis keys or restore the removed HTTP
routes. If the application binary must be rolled back, first coordinate all
API and Console callers because endpoint rollback is intentionally not
supported; data rollback is unnecessary and destructive cleanup is prohibited.
