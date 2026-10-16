# Administrative account deletion

Use Console Identity → Users. Tenant access removal edits one direct assignment;
global account deletion removes the Tikti UID and its identity access in every
tenant. Inherited group access is not removed by the tenant-only action. Global
deletion is platform-admin only and refuses the current operator's own account.
The confirmation must identify the person and global reach, and state that the
external SAML identity remains capable of provisioning a new account on login.

The supported private HTTP operation is documented in
`docs/openapi/identity-user-deletion.yaml`. Read the person/access projection,
then DELETE that exact UID with `If-Match: "<version>"` and no body/query.
Never reuse the legacy `/accounts/delete` self-service endpoint for admin work.
A 204 is complete/already absent; 412 requires refreshing and reviewing the
person; 403 means insufficient/current-changed authority or self-deletion.
Malformed conditions return 400. There is no wildcard retry or force option.

A 500 can mean ambiguous canonical data, inconsistent ownership/reverse links,
exceeded relationship bounds, unavailable storage or exhausted transaction
retries. The operation validates before MULTI and fails without partial logical
cleanup for invariant/type failures. Retain the request ID and inspect only the
exact actor/target metadata through authorized diagnostics. Do not scan secrets,
log tokens, repair ownership manually or bypass the conditional deletion.

Old identity/access tokens cannot authorize the deleted UID. Existing OOB
payloads are not globally scanned; bound ones cannot authenticate another UID
and expire within 900 seconds. Pre-upgrade unbound sign-in/reset codes are
rejected after promotion, so request a new code. Rates, anti-enumeration and
public request/response fields are unchanged. Revoked tokenVersion, suspended or
SAML accounts cannot consume password credentials as current authority.

At minute 5 after a regression, disable the Console action and retain request
IDs. At minute 15, restore the retained previous changed-component images if the
failure is code-related. At minute 60, inspect the exact transaction and audited
intent/outcome; no manual deletion is a recovery step. Binary rollback target is
under 10 minutes and does not recover deleted accounts. The preceding guard-only
Tikti release is the minimum rollback baseline after any real account deletion. Restore that retained working image, never an older
binary: disabling the administrative route alone cannot stop legacy-account
resurrection or email-bound OOB authentication on an old binary.
Use synthetic tests for acceptance; never delete a production account as a drill.
