# SAML Post-Launch Observability Report

**Observation window:** 72 hours after GA flip  
**Owner:** on-call SRE + SAML feature lead  
**Depends on:** P10.5 (GA release)  
**References:**  
- [SAML HLD §18 — Observability](../12_saml_federation_hld.md)  
- [SAML Alert Playbook](../saml/alert-playbook.md)  
- [SAML Troubleshooting Guide](../saml/troubleshooting.md)  
- [Operations and SLO](../07_operations_and_slo.md)  

---

## 1. Acceptance Criteria

| # | Criterion | Target | Status |
|---|-----------|--------|--------|
| AC-1 | Alert budget consumed | < 20 % | ☐ |
| AC-2 | SAML ACS P95 latency within SLO | < 150 ms | ☐ |
| AC-3 | Customer-reported auth failures | 0 | ☐ |

---

## 2. Alert Budget

### 2.1 Definition

The alert budget measures the fraction of the 72-hour window during
which a SAML-related Prometheus alert was firing. A budget below 20 %
means alerts consumed fewer than **14 hours 24 minutes** of the window.

### 2.2 Alerts in Scope

| Alert | Severity | Metric | Threshold |
|-------|----------|--------|-----------|
| `SAMLSPCertExpiringSoon` | warning | `tikti_saml_sp_cert_expiry_seconds` | < 30 days |
| `SAMLIdPCertExpiringSoon` | warning | `tikti_saml_idp_cert_expiry_seconds` | < 14 days |
| `SAMLMetadataRefreshFailure` | warning | `tikti_saml_metadata_refresh_total{result="error"}` | 2 consecutive failures |
| `SAMLValidationFailureSpike` | critical | `tikti_saml_validation_failures_total{reason}` | rate > 5/min per reason |

### 2.3 PromQL — Budget Consumption

```promql
# Fraction of the window any SAML alert was firing
avg_over_time(
  ALERTS{alertname=~"SAML.*", alertstate="firing"}[72h]
)
```

Record the result in AC-1 above.

---

## 3. P95 Latency

### 3.1 SLO Target

Per [HLD Appendix G](../12_saml_federation_hld.md), the SAML ACS
response-validation P95 must stay below **150 ms**.

### 3.2 PromQL — P95 over 72 h

```promql
# SAML ACS P95 latency (seconds → milliseconds)
histogram_quantile(0.95,
  sum(rate(tikti_saml_response_validation_duration_seconds_bucket[72h])) by (le)
) * 1000
```

### 3.3 Supporting Queries

```promql
# IdP round-trip P95
histogram_quantile(0.95,
  sum(rate(tikti_saml_idp_roundtrip_duration_seconds_bucket[72h])) by (le)
) * 1000

# Per-tenant P95 (top 5 slowest)
topk(5,
  histogram_quantile(0.95,
    sum(rate(tikti_saml_response_validation_duration_seconds_bucket[72h])) by (le, tid)
  ) * 1000
)
```

Record the result in AC-2 above.

---

## 4. Customer-Reported Auth Failures

### 4.1 Log Inspection

Search structured logs and audit records for rejected SAML assertions
during the observation window:

```promql
# Total validation failures by reason
sum by (reason)(
  increase(tikti_saml_validation_failures_total[72h])
)
```

```promql
# Total validation failures by tenant
sum by (tid)(
  increase(tikti_saml_validation_failures_total[72h])
)
```

### 4.2 Support Ticket Review

- Review the support queue for tickets tagged **SAML** or
  **authentication** opened during the 72-hour window.
- Cross-reference any reported failures with audit log entries
  (`event:"saml.assertion", decision:"reject"`).

Record the result in AC-3 above.

---

## 5. Supplementary Metrics

Capture the following counters at the end of the 72-hour window for the
release record:

| Metric | PromQL |
|--------|--------|
| Total SAML authn requests | `sum(increase(tikti_saml_authn_requests_total[72h]))` |
| Total SAML responses (success) | `sum(increase(tikti_saml_responses_total{result="success"}[72h]))` |
| Total SAML responses (error) | `sum(increase(tikti_saml_responses_total{result!="success"}[72h]))` |
| Total JIT provisions | `sum(increase(tikti_saml_jit_provisions_total[72h]))` |
| Total replay blocks | `sum(increase(tikti_saml_replay_blocked_total[72h]))` |
| Total metadata refreshes (ok) | `sum(increase(tikti_saml_metadata_refresh_total{result="success"}[72h]))` |
| Total metadata refreshes (error) | `sum(increase(tikti_saml_metadata_refresh_total{result="error"}[72h]))` |
| Total logout requests | `sum(increase(tikti_saml_logout_requests_total[72h]))` |

---

## 6. Grafana Dashboard

The [SAML Grafana dashboard](../grafana/saml.json) provides real-time
panels for the metrics above. Verify the dashboard is loading correctly
in the production Grafana instance during the observation window.

---

## 7. Escalation Procedure

If any acceptance criterion is not met:

1. **AC-1 breach (alert budget ≥ 20 %):** Identify the dominant firing
   alert via the [Alert Playbook](../saml/alert-playbook.md), apply the
   documented response, and extend the observation window by 24 hours.
2. **AC-2 breach (P95 ≥ 150 ms):** Isolate the slowest tenant(s) using
   the per-tenant query in §3.3. Check Redis latency, IdP metadata
   fetch duration, and assertion payload sizes. Consult
   [HLD Appendix G](../12_saml_federation_hld.md) for the performance
   budget breakdown.
3. **AC-3 breach (customer-reported failure):** Open a P1 incident,
   correlate with audit logs, and follow the
   [Troubleshooting Guide](../saml/troubleshooting.md). Rollback is
   available by setting `saml.enabled=false` in Helm values.

---

## 8. Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| SRE on-call | | | ☐ |
| SAML feature lead | | | ☐ |
| Engineering manager | | | ☐ |
