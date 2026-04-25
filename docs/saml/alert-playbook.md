# SAML Alert Playbook

This document lists Prometheus alerts related to the SAML subsystem and
the recommended operator response for each.

## SAMLSPCertExpiringSoon

| Field | Value |
|---|---|
| **Metric** | `tikti_saml_sp_cert_expiry_seconds` |
| **Condition** | Value falls below 30 days (2592000 seconds) |
| **Severity** | warning |

**Runbook:** [SP Key Rotation Runbook](key-rotation.md)

### Response

1. Open the [SP Key Rotation Runbook](key-rotation.md) and execute
   **Step 1 — Prepare** to generate a new key pair and publish dual-cert
   metadata.
2. Distribute the updated metadata to all IdPs.
3. Wait at least 72 hours for IdP metadata caches to refresh.
4. Execute **Step 2 — Commit** to publish single-cert metadata with only
   the new certificate.
5. Verify SSO is working (see the **Verification** section of the runbook).

## SAMLIdPCertExpiringSoon

| Field | Value |
|---|---|
| **Metric** | `tikti_saml_idp_cert_expiry_seconds{tid,subject}` |
| **Condition** | Value falls below 14 days (1209600 seconds) |
| **Severity** | warning |

### Response

1. Contact the IdP administrator for the affected tenant (`tid` label)
   and request a metadata refresh URL or updated certificate.
2. Update the IdP metadata:
   ```bash
   tikti saml idp update --tid <TID> --metadata-url <NEW_URL>
   ```
3. Confirm the new certificate is loaded:
   ```bash
   tikti saml idp show --tid <TID> --json | jq '.cert_expiry'
   ```

## SAMLMetadataRefreshFailure

| Field | Value |
|---|---|
| **Metric** | `tikti_saml_metadata_refresh_total{tid,result="error"}` |
| **Condition** | 2 consecutive failures (see HLD §26 Risk #2) |
| **Severity** | warning |

### Response

1. Check network connectivity to the IdP metadata URL:
   ```bash
   tikti saml idp show --tid <TID> --json | jq '.metadata_url'
   curl -sI <METADATA_URL>
   ```
2. If the URL is unreachable, contact the IdP administrator.
3. If the URL returns invalid XML, fetch and re-register:
   ```bash
   tikti saml idp update --tid <TID> --metadata-url <METADATA_URL>
   ```

## SAMLValidationFailureSpike

| Field | Value |
|---|---|
| **Metric** | `tikti_saml_validation_failures_total{tid,reason}` |
| **Condition** | Rate exceeds 5 per minute for any single `reason` |
| **Severity** | critical |

### Response

1. Inspect the `reason` label to determine the failure type (see
   `docs/saml/troubleshooting.md` for reason codes).
2. Check whether the spike correlates with a recent IdP certificate
   rotation (`reason=signature_invalid`) — if so, force a metadata
   refresh:
   ```bash
   tikti saml idp fetch --tid <TID>
   ```
3. If the reason is `clock_skew`, verify NTP synchronisation on the SP
   host and check the `observed_clock_skew_seconds{tid}` gauge.
4. Escalate to the on-call engineer if the spike persists after
   mitigation.
