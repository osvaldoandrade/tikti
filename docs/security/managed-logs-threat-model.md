# Managed Logs exchange threat model

Task: CFP-115; date: 2026-10-19

## Assets and trust boundaries

The assets are short-lived ingest assertions, per-topic CodeQ credentials and
tenant routing authority. A tenant application may control every byte in its
logs. It cannot choose the projected collector subject, provider clusterRef,
SA UID or Pod UID that Tikti verifies. Installation configuration and the
managed collector are trusted. The API source authority is a separate service
principal and only observes current control-plane resources.

V1 delegates log provenance by **cluster**, not by node. A compromised managed
collector can forge source metadata inside that delegated cluster; this feature
does not claim cryptographic node or individual log-event attestation. The
gateway must strip reserved application attributes, use informer-enriched native
UIDs, and ask Code Admin to match tenant placement and source configuration.

## Abuse cases and controls

- A forged or unbound projected JWT cannot obtain a Logs grant: canonical
  subject, trusted provider, exact audience, signed UIDs and expiry are required.
- Tenant and topic injection cannot broaden a grant: Ingest/Resolve have no
  tenant selectors; Publish matches an enabled config lifetime. Subscribe may
  select that config or the real retained policy lifetime, so accepted work can
  drain after collection stops. Both require one ACTIVE tenant and the exact
  `cf-logs` topic and policy. A retained policy grant cannot publish, ingest or
  resolve sources; unknown/mixed kinds and changed native lifetimes are refused.
- A caller cannot combine the Logs selector with legacy CodeQ selectors, admin
  scopes or an arbitrary audience. Every Logs attempt is handled explicitly.
- A compromised or redirected authority cannot silently change tenant/topic:
  the response is size-limited, strictly decoded and matched to the request.
  Proxy environment variables and HTTP redirects are not followed.
- Dependency outage or saturation refuses issuance. There is no stale grant
  fallback; limits bound in-flight work and per-identity request rate.
- Existing issued JWTs are bearer tokens. Possession permits their exact
  authority until expiry; they are not sender-constrained. TLS and the 300-second
  maximum lifetime bound that residual risk. No token/body is emitted in errors.

The human operations permission for platform log queries is outside these
workload grants. A collector token is never a human query token, and no Logs
exchange issues a tenant-admin or platform-admin role.

The reserved `code-admin:logs:platform:read` scope is global/nonassignable in
the canonical offline registry. Tenant-role expansion, including legacy
non-discovery exchange paths, cannot delegate it. It must be explicitly
requested within an existing audience/client ceiling and backed by the current
MASTER platform identity. Role ADMIN and client default scopes alone do not
qualify; removing the direct platform assignment invalidates later issuance
and Tikti bearer validation. Downstream APIs accept no external `console:`
alias for this new privilege.
