# SAML ACS Load Test

k6 load test that targets `POST /saml/acs` at 500 requests per second for
5 minutes with pre-generated signed SAML responses.

**SLO targets** (from HLD §24 / Appendix G):

| Metric | Threshold |
|--------|-----------|
| P95 latency | < 150 ms |
| Error rate | < 0.01 % |

## Prerequisites

1. **k6** ≥ v0.47 — <https://k6.io/docs/get-started/installation/>
2. A running Tikti instance with SAML enabled and a configured IdP/tenant.
3. Pre-generated signed SAML responses (base64-encoded, one per file).

## Generating Signed SAML Responses

Before running the load test you need a JSON file containing pre-generated,
validly signed SAML responses that the ACS handler will accept.  The file
must be a JSON array of base64-encoded `<samlp:Response>` strings.

```bash
# Example: use the tikti-cli helper to produce N unique responses
# and collect them into a JSON array.
responses="["
for i in $(seq 1 100); do
  resp=$(tikti-cli saml test-response \
    --tid "load-tenant" \
    --email "user${i}@load.test" \
    --sp-key hack/saml/sp.key \
    --sp-cert hack/saml/sp.crt)
  [ "$i" -gt 1 ] && responses="${responses},"
  responses="${responses}\"${resp}\""
done
responses="${responses}]"
echo "$responses" > test/load/responses.json
```

You must also seed Redis with matching `RequestRecord` entries whose IDs
correspond to the `STATE_COOKIE` value used by the script (default:
`preloaded-req-id`).

## Running

```bash
# Default — 500 RPS, 5 min, localhost:8080
k6 run test/load/saml_acs.js

# Custom target and duration
k6 run \
  -e BASE_URL=https://staging.example.com \
  -e RESPONSES_FILE=./test/load/responses.json \
  -e STATE_COOKIE=preloaded-req-id \
  -e TARGET_RPS=500 \
  -e DURATION=5m \
  test/load/saml_acs.js
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_URL` | `http://localhost:8080` | Tikti base URL |
| `RESPONSES_FILE` | `./test/load/responses.json` | JSON array of base64-encoded SAML responses |
| `STATE_COOKIE` | `preloaded-req-id` | Value for the `tikti_saml_state` cookie |
| `TARGET_RPS` | `500` | Target requests per second |
| `DURATION` | `5m` | Test duration |

## Output

The script produces:

1. **Console summary** — key latency percentiles and error rate.
2. **`test/load/baseline.json`** — machine-readable baseline snapshot
   (committed to the repo after each accepted run).

## Dashboard

The Tikti Prometheus metrics exposed during the test can be visualized in
Grafana.  The relevant histogram is:

```
tikti_saml_response_validation_duration_seconds{tid="<tenant>"}
```

Buckets: `.005, .01, .025, .05, .1, .25, .5, 1`  (HLD §18 / App. G).

Import the panel from `helm/grafana/dashboards/` or create a histogram panel
with the query:

```promql
histogram_quantile(0.95,
  sum(rate(tikti_saml_response_validation_duration_seconds_bucket[1m])) by (le)
)
```

## Baseline

After a successful load test run the script writes `test/load/baseline.json`.
Commit this file to record the current performance baseline.  Example:

```json
{
  "timestamp": "2026-04-25T14:00:00.000Z",
  "target_rps": 500,
  "duration": "5m",
  "p50_ms": 12.5,
  "p90_ms": 45.2,
  "p95_ms": 78.3,
  "p99_ms": 120.1,
  "error_rate": 0,
  "total_requests": 150000,
  "thresholds_passed": true
}
```

## Interpreting Failures

| Failure | Likely cause |
|---------|--------------|
| P95 > 150 ms | Redis latency, GC pressure, or CPU saturation |
| Error rate > 0.01 % | State cookie mismatch, expired responses, or Redis OOM |
| `status is 302` check fails | ACS rejected responses — check server logs |

## References

- HLD §24 — Testing Strategy
- HLD Appendix G — Performance Budget (150 ms P95 breakdown)
