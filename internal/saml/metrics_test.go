package saml

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// gather is a test helper that collects all metric families from a registry.
func gather(t *testing.T, reg *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := make(map[string]*dto.MetricFamily, len(fams))
	for _, f := range fams {
		out[f.GetName()] = f
	}
	return out
}

// TestMetrics_AllPresent ensures all series defined in HLD §18 are
// registered after calling NewMetrics.
func TestMetrics_AllPresent(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	// Touch every collector once so that Gather returns them.
	m.AuthnRequests.WithLabelValues("t1").Inc()
	m.Responses.WithLabelValues("t1", "ok").Inc()
	m.ValidationFailures.WithLabelValues("t1", "clock_skew").Inc()
	m.JITProvisions.WithLabelValues("t1").Inc()
	m.LogoutRequests.WithLabelValues("t1").Inc()
	m.LogoutResponses.WithLabelValues("t1", "ok").Inc()
	m.MetadataRefresh.WithLabelValues("t1", "ok").Inc()
	m.ReplayBlocked.WithLabelValues("t1").Inc()
	m.TIDOverrideIgnored.WithLabelValues("t1").Inc()
	m.IdPAdminChanges.WithLabelValues("update", "ok").Inc()
	m.ValidationDuration.WithLabelValues("t1").Observe(0.042)
	m.IdPRoundtrip.WithLabelValues("t1").Observe(0.15)
	m.IdPCertExpiry.WithLabelValues("t1", "CN=idp").Set(86400)
	m.SPCertExpiry.Set(172800)
	m.RefreshConsecFailures.WithLabelValues("t1").Set(0)
	for _, result := range []string{"repost", "success", "failure"} {
		m.StateCookieRecovery.WithLabelValues(result).Inc()
	}

	fams := gather(t, reg)

	want := []string{
		"tikti_saml_authn_requests_total",
		"tikti_saml_responses_total",
		"tikti_saml_validation_failures_total",
		"tikti_saml_jit_provisions_total",
		"tikti_saml_logout_requests_total",
		"tikti_saml_logout_responses_total",
		"tikti_saml_metadata_refresh_total",
		"tikti_saml_replay_blocked_total",
		"tikti_saml_tid_override_ignored_total",
		"tikti_saml_idp_admin_changes_total",
		"tikti_saml_response_validation_duration_seconds",
		"tikti_saml_idp_roundtrip_duration_seconds",
		"tikti_saml_idp_cert_expiry_seconds",
		"tikti_saml_sp_cert_expiry_seconds",
		"tikti_saml_metadata_refresh_consec_failures",
		"tikti_saml_state_cookie_recovery_total",
	}

	if len(fams) != len(want) {
		t.Errorf("expected %d metric families, got %d", len(want), len(fams))
	}

	for _, name := range want {
		if _, ok := fams[name]; !ok {
			t.Errorf("metric %q not found in registry", name)
		}
	}

	recovery := fams["tikti_saml_state_cookie_recovery_total"]
	if got := len(recovery.GetMetric()); got != 3 {
		t.Errorf("state cookie recovery: expected 3 bounded result series, got %d", got)
	}
}

// TestMetrics_LabelCardinality verifies that each counter-vec with a "tid"
// label only produces as many time-series as there are distinct tid values,
// preventing cardinality blow-ups.
func TestMetrics_LabelCardinality(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	tids := []string{"tenant-a", "tenant-b", "tenant-c"}
	for _, tid := range tids {
		m.AuthnRequests.WithLabelValues(tid).Inc()
		m.Responses.WithLabelValues(tid, "ok").Inc()
		m.ReplayBlocked.WithLabelValues(tid).Inc()
	}

	fams := gather(t, reg)

	// authn_requests_total should have exactly len(tids) series.
	if f, ok := fams["tikti_saml_authn_requests_total"]; ok {
		if got := len(f.GetMetric()); got != len(tids) {
			t.Errorf("authn_requests_total: expected %d series, got %d", len(tids), got)
		}
	} else {
		t.Fatal("tikti_saml_authn_requests_total missing")
	}

	// replay_blocked_total should have exactly len(tids) series.
	if f, ok := fams["tikti_saml_replay_blocked_total"]; ok {
		if got := len(f.GetMetric()); got != len(tids) {
			t.Errorf("replay_blocked_total: expected %d series, got %d", len(tids), got)
		}
	} else {
		t.Fatal("tikti_saml_replay_blocked_total missing")
	}
}

// TestMetrics_ValidationDurationBuckets checks that the histogram buckets
// match the HLD §18 / Appendix G specification exactly.
func TestMetrics_ValidationDurationBuckets(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.ValidationDuration.WithLabelValues("t1").Observe(0.042)

	fams := gather(t, reg)
	f, ok := fams["tikti_saml_response_validation_duration_seconds"]
	if !ok {
		t.Fatal("tikti_saml_response_validation_duration_seconds missing")
	}

	metrics := f.GetMetric()
	if len(metrics) == 0 {
		t.Fatal("no metrics in histogram family")
	}

	h := metrics[0].GetHistogram()
	buckets := h.GetBucket()

	wantBounds := []float64{.005, .01, .025, .05, .1, .25, .5, 1}
	if len(buckets) != len(wantBounds) {
		t.Fatalf("expected %d buckets, got %d", len(wantBounds), len(buckets))
	}
	for i, b := range buckets {
		if b.GetUpperBound() != wantBounds[i] {
			t.Errorf("bucket[%d]: got %v, want %v", i, b.GetUpperBound(), wantBounds[i])
		}
	}
}

// TestMetrics_HermeticRegistry confirms that two independent registries
// do not interfere with each other — proving no global state is used.
func TestMetrics_HermeticRegistry(t *testing.T) {
	reg1 := prometheus.NewRegistry()
	reg2 := prometheus.NewRegistry()

	m1 := NewMetrics(reg1)
	_ = NewMetrics(reg2) // must not panic (duplicate registration)

	m1.AuthnRequests.WithLabelValues("t1").Inc()

	fams1 := gather(t, reg1)
	fams2 := gather(t, reg2)

	if _, ok := fams1["tikti_saml_authn_requests_total"]; !ok {
		t.Error("reg1 should contain authn_requests_total")
	}
	// reg2 was never touched, so no series should appear.
	if f, ok := fams2["tikti_saml_authn_requests_total"]; ok {
		if len(f.GetMetric()) != 0 {
			t.Error("reg2 should have 0 series for authn_requests_total")
		}
	}
}
