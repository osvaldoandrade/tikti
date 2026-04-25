// test/load/saml_acs.js — k6 load-test for POST /saml/acs
//
// Sends 500 RPS of pre-generated signed SAML responses for 5 minutes.
// SLO: P95 < 150 ms, error rate < 0.01 %.
//
// Usage:
//   k6 run test/load/saml_acs.js                         # defaults
//   k6 run -e BASE_URL=https://staging.example.com \
//          -e RESPONSES_FILE=./responses.json test/load/saml_acs.js
//
// Environment variables:
//   BASE_URL        – Tikti base URL             (default: http://localhost:8080)
//   RESPONSES_FILE  – JSON file with an array of base64-encoded SAML responses
//                     (default: ./test/load/responses.json)
//   STATE_COOKIE    – value for the tikti_saml_state cookie the ACS handler
//                     expects (must match a request stored in Redis)
//   TARGET_RPS      – requests per second         (default: 500)
//   DURATION        – test duration               (default: 5m)

import http from "k6/http";
import { check } from "k6";
import { Rate, Trend } from "k6/metrics";
import { SharedArray } from "k6/data";

// ── Custom metrics ─────────────────────────────────────────────────────
const errorRate = new Rate("saml_acs_errors");
const acsDuration = new Trend("saml_acs_duration", true); // in ms

// ── Configuration ──────────────────────────────────────────────────────
const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";
const RESPONSES_FILE =
  __ENV.RESPONSES_FILE || "./test/load/responses.json";
const STATE_COOKIE = __ENV.STATE_COOKIE || "preloaded-req-id";
const TARGET_RPS = parseInt(__ENV.TARGET_RPS || "500", 10);
const DURATION = __ENV.DURATION || "5m";

// ── Pre-generated signed SAML responses (shared across VUs) ────────────
// The responses file must be a JSON array of base64-encoded SAMLResponse
// strings.  During init the file is loaded once and shared across all VUs
// via SharedArray so that memory usage stays constant regardless of VU count.
//
// If the file does not exist (e.g. in a CI dry-run), a single synthetic
// payload is used so the script can still validate options and thresholds.

// Fallback payload: a minimal base64-encoded <samlp:Response> placeholder.
// Real load tests MUST supply pre-generated signed responses.
const FALLBACK_RESPONSE =
  "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6" +
  "dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJfbG9hZHRlc3QiIFZlcnNpb249" +
  "IjIuMCIgSXNzdWVJbnN0YW50PSIyMDI2LTA0LTI1VDAwOjAwOjAwWiI+PC9z" +
  "YW1scDpSZXNwb25zZT4=";

let rawData;
try {
  rawData = open(RESPONSES_FILE);
} catch (_) {
  rawData = null;
}

const samlResponses = new SharedArray("responses", function () {
  if (rawData) {
    const parsed = JSON.parse(rawData);
    if (Array.isArray(parsed) && parsed.length > 0) {
      return parsed;
    }
  }
  return [FALLBACK_RESPONSE];
});

// ── k6 options ─────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    saml_acs_load: {
      executor: "constant-arrival-rate",
      rate: TARGET_RPS,
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: Math.min(TARGET_RPS, 200),
      maxVUs: Math.min(TARGET_RPS * 2, 1000),
    },
  },

  thresholds: {
    // P95 response time < 150 ms  (HLD §24 / App. G)
    http_req_duration: ["p(95)<150"],
    saml_acs_duration: ["p(95)<150"],
    // Error rate < 0.01 %
    saml_acs_errors: ["rate<0.0001"],
    // Additional guardrails
    http_req_failed: ["rate<0.0001"],
  },
};

// ── Default function (executed per VU iteration) ───────────────────────
export default function () {
  // Pick a random pre-generated response for this iteration.
  const idx = Math.floor(Math.random() * samlResponses.length);
  const samlResponse = samlResponses[idx];

  const url = `${BASE_URL}/saml/acs`;

  const params = {
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    cookies: {
      tikti_saml_state: STATE_COOKIE,
    },
    tags: { name: "POST /saml/acs" },
  };

  const payload = `SAMLResponse=${encodeURIComponent(samlResponse)}&RelayState=${encodeURIComponent("/dashboard")}`;

  const res = http.post(url, payload, params);

  // Record custom metrics.
  acsDuration.add(res.timings.duration);

  const ok = check(res, {
    "status is 302 (redirect)": (r) => r.status === 302,
    "has Location header": (r) => r.headers["Location"] !== undefined,
    "no server error": (r) => r.status < 500,
  });

  errorRate.add(!ok);
}

// ── Lifecycle hooks ────────────────────────────────────────────────────
export function handleSummary(data) {
  const p95 = data.metrics.http_req_duration
    ? data.metrics.http_req_duration.values["p(95)"]
    : null;
  const errRate = data.metrics.saml_acs_errors
    ? data.metrics.saml_acs_errors.values.rate
    : null;

  const baseline = {
    timestamp: new Date().toISOString(),
    target_rps: TARGET_RPS,
    duration: DURATION,
    p50_ms: data.metrics.http_req_duration
      ? data.metrics.http_req_duration.values["p(50)"]
      : null,
    p90_ms: data.metrics.http_req_duration
      ? data.metrics.http_req_duration.values["p(90)"]
      : null,
    p95_ms: p95,
    p99_ms: data.metrics.http_req_duration
      ? data.metrics.http_req_duration.values["p(99)"]
      : null,
    error_rate: errRate,
    total_requests: data.metrics.http_reqs
      ? data.metrics.http_reqs.values.count
      : 0,
    thresholds_passed: !Object.values(data.root_group?.checks || {}).some(
      (c) => c.fails > 0
    ),
  };

  console.log(`\n── SAML ACS Load Test Baseline ──`);
  console.log(`P95 latency : ${p95 != null ? p95.toFixed(2) + " ms" : "N/A"}`);
  console.log(
    `Error rate  : ${errRate != null ? (errRate * 100).toFixed(4) + " %" : "N/A"}`
  );
  console.log(`Total reqs  : ${baseline.total_requests}`);
  console.log(`──────────────────────────────────\n`);

  return {
    "test/load/baseline.json": JSON.stringify(baseline, null, 2) + "\n",
    stdout: textSummary(data, { indent: " ", enableColors: true }),
  };
}

// Minimal text summary helper (k6 built-in is only available in newer
// versions; provide a small fallback that prints key metrics).
function textSummary(data, _opts) {
  const lines = ["", "=== SAML ACS Load Test Summary ===", ""];
  for (const [name, metric] of Object.entries(data.metrics || {})) {
    if (metric.values) {
      const parts = Object.entries(metric.values)
        .map(([k, v]) => `${k}=${typeof v === "number" ? v.toFixed(2) : v}`)
        .join(", ");
      lines.push(`  ${name}: ${parts}`);
    }
  }
  lines.push("");
  return lines.join("\n");
}
