# ADR 0009: Subject-bound account credentials and canonical lookup

Status: accepted for implementation, 2026-10-16. This independently deployable
security guard precedes administrative account deletion in ADR 0010.

Email aliases can be reused, renamed or shared with federated principals. An
old email-sign-in/reset credential must never authenticate a new immutable UID.
Legacy email reads must not repopulate a removed or newer canonical user after
the existing Identity V2 startup backfill has completed.

Bind the issuer-resolved UID and TokenVersion to the existing 900-second OOB
payload. Consume atomically, then resolve and validate only that UID/generation,
active status and password eligibility. Password reset keeps existing Revision
CAS. Existing Redis implements this explicit repository contract; it never falls
back to legacy email proof. Older test/adaptor contracts remain source-compatible.
Public request/response fields, rates and anti-enumeration do not change. Unbound
codes issued before promotion are rejected and must be requested again.

Use the existing completed-backfill marker as the canonical-source boundary.
Once its value is v1, email lookup never reads/imports legacy hashes. Before
completion, retain compatibility through WATCH/MULTI across marker, exact UID,
canonical and federated hashes, email alias, legacy hash and directory index.
A current UID is never overwritten by legacy input, and an in-flight import
cannot commit after the marker changes. No new store, scan, tombstone or backfill
is introduced. Authentication/storage errors fail closed.

Publish and deploy this guard-only source TAG/image before the separate account
removal feature. Verify existing login/read behavior without deleting any real
account and retain this working image. After a real account deletion, this guard
is the oldest permitted Tikti rollback baseline. Older binaries may resurrect
legacy UIDs or accept email-bound credentials even with the DELETE route off;
rolling back only the UI is insufficient. Binary rollback does not restore
removed accounts. The guard itself has no destructive migration.
