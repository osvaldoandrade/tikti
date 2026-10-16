# Account credential guard rollout

Publish the guard-only Tikti TAG/image independently from administrative account
deletion, deploy it first, and retain its working image for rollback. No
production account needs to be deleted for this verification. Public login and
reset contracts/rates stay unchanged, except that a sign-in/reset code issued
before the guard must be requested again. Its previous lifetime was 900 seconds.

Existing production startup already marks Identity V2 backfill complete. With
that marker set to v1, legacy email records are inert and are never imported at
request time. Do not clear/change the marker or edit identity ownership manually.
Before completion, a bounded WATCH/MULTI import protects the same boundary.

After the first real administrative deletion, never restore Tikti older than
this retained guard-only image. The administrative feature can be removed by
rolling back to the guard. An older binary can resurrect a legacy UID even if
its UI and DELETE endpoint are disabled. No binary rollback restores deleted
accounts. Existing audit data and unrelated workloads remain unchanged.
