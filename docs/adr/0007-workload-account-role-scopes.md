# ADR 0007: Issue workload account scopes from exact tenant roles

## Status

Proposed for the WeCare administrative workspace on 2026-10-03.

## Context

The WeCare account broker currently exchanges every authorized account for the
same two audience scopes. The application requires domain scopes for its
administrative routes. Adding those scopes to the base `wecare-user` role would
give every registered member administrative authority.

## Decision

Keep the existing registration role and audience scopes as the base contract.
An installation may declare up to eight sorted `additionalRoles`, each with an
exact tenant-prefixed, sorted scope set. Tikti does not create or modify these
administrator-owned roles. Reconciliation expands only the managed audience's
scope ceiling to the configured union. It does not require an additional role
to exist at bootstrap, so a missing role cannot stop the identity service.

At sign-in, Tikti reads the user's effective roles for the exact tenant. It
requests only the union of scopes associated with roles the user actually
holds. No matching role means `403`. Token exchange independently checks that
the requested scopes belong to both the managed audience and the user's
resolved role permissions. A missing role or permission denies that account's
session. Registration continues to assign only the base role. A broker request
still accepts no tenant, role, audience or scope input.

## Rollout and rollback

Release Tikti before adding the WeCare additional role to the installation.
Verify the existing role permissions before deployment, then let the
installation reconcile the audience ceiling. Confirm the exact membership
assignment for an approved administrator, that an ordinary `wecare-user` token
has only the two base scopes, and that an administrator token has the configured
domain scopes. Enable application operations only after its separate release
gates and cross-role checks pass.

Removing the additional role from installation config returns future sessions
to the base contract and removes the expanded managed audience ceiling. Do not
erase an assigned role or previously issued token as part of rollback; allow
the bounded token lifetime to expire or revoke the assignment when needed.
