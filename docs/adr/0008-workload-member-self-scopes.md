# ADR 0008: Migrate exact workload member scopes

## Status

Proposed for WeCare member access on 2026-10-03. Production activation requires a reviewed installation change.

## Context

The `wecare-user` role currently has only `wecare-social-api:read` and
`wecare-social-api:write`. Registration assigns that role, but WeCare's own
application, referral, intake, benefit, and delivery routes require exact
`wecare:*:self` scopes. Existing members therefore receive a valid session
without the scopes needed to use those routes. Administrative scopes stay in
the separate `wecare-erp-admin` role.

The base role and managed audience are installation-owned. The old reconciler
requires an exact role match, so merely adding scopes to values prevents Tikti
bootstrap from succeeding.

## Decision

Keep the base role name and its workload audience scopes. Add a sorted
`memberScopes` list containing only exact tenant-prefixed `:self` scopes. The
role definition and managed audience ceiling become the union of the base and
member scopes. At sign-in, those scopes are requested only if the account has
the base role. Additional roles remain independent.

An installation changing the existing role supplies the exact sorted
`previousBaseRoleScopes`. Reconciliation compares the stored role to that
definition and uses a Redis compare-and-swap to replace only that role. An
unexpected definition, different tenant, invalid scope, or concurrent write
fails closed. No membership assignment or account record is rewritten. A
replay with the desired definition is a no-op. The new fields are absent for
existing broker clients, including Bereia.

## Compatibility and rollout

The HTTP request and response formats do not change. Existing API and Web
versions ignore the additional token scopes; member routes requiring them
start working after token renewal. Old Tikti code cannot reconcile an expanded
role, so release the new Tikti version with the old values first. Then apply
the reviewed WeCare values through the installation-owned plan and deployment
workflow. Verify exact role permissions, managed audience scopes, a normal
member session, an administrator session, and denial of administrative routes
to the normal member. Wait at least the 900-second token lifetime before
assessing all existing sessions.

If the role definition or managed audience differs from the declared state,
abort deployment. Inspect the exact tenant records and do not overwrite them.
Monitor sign-in 403/5xx rates and the WeCare API's scope-denied counters.

## Rollback

Keep the new Tikti binary installed. Supply the expanded role's exact sorted
permissions as `previousBaseRoleScopes`, remove `memberScopes`, and apply the
installation plan. This atomically restores the old role and managed audience
scope ceiling. Wait for the 900-second session lifetime, then revert the Tikti
binary if necessary. Role assignments and WeCare data remain untouched.

## Alternatives

Creating a second member role would require an assignment backfill and would
leave existing registered users without personal scopes. Giving `wecare-user`
administrative scopes would grant those actions to every registrant. A manual
role overwrite has no exact prior-state check or repeatable rollback.
