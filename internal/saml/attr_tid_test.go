package saml

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// counterValue returns the current value of a CounterVec for the given label,
// or -1 if the metric is not found.
func counterValue(t *testing.T, reg *prometheus.Registry, name, label string) float64 {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "tid" && lp.GetValue() == label {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return -1
}

// TestTID_AssertionOverride_Ignored verifies that tid-like attributes in the
// assertion are stripped and the URL tid is preserved.
func TestTID_AssertionOverride_Ignored(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	attrs := map[string][]string{
		"tid":       {"evil-tenant"},
		"tenant_id": {"evil-tenant-2"},
		"tenantId":  {"evil-tenant-3"},
		"email":     {"user@example.com"},
		"name":      {"Test User"},
	}

	out := MapAttributes(attrs, "url-tenant", m)

	// tid-like keys must be absent.
	for _, k := range []string{"tid", "tenant_id", "tenantId"} {
		if _, ok := out[k]; ok {
			t.Errorf("expected %q to be stripped, but it is present", k)
		}
	}

	// Legitimate attributes must survive.
	if out["email"][0] != "user@example.com" {
		t.Errorf("email = %v, want [user@example.com]", out["email"])
	}
	if out["name"][0] != "Test User" {
		t.Errorf("name = %v, want [Test User]", out["name"])
	}
}

// TestTID_Metric_Increments verifies that the counter is incremented once per
// stripped attribute.
func TestTID_Metric_Increments(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	attrs := map[string][]string{
		"tid":   {"evil"},
		"email": {"a@b.com"},
	}

	_ = MapAttributes(attrs, "t-123", m)

	val := counterValue(t, reg, "tikti_saml_tid_override_ignored_total", "t-123")
	if val != 1 {
		t.Errorf("tikti_saml_tid_override_ignored_total = %v, want 1", val)
	}
}

// TestTID_NoAttribute_NoMetric verifies that no metric is emitted when no
// tid-like attribute is present (typical case).
func TestTID_NoAttribute_NoMetric(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	attrs := map[string][]string{
		"email": {"a@b.com"},
		"name":  {"User"},
	}

	_ = MapAttributes(attrs, "t-456", m)

	// Gather and check that the metric family either does not exist
	// or has no series for tid=t-456.
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != "tikti_saml_tid_override_ignored_total" {
			continue
		}
		for _, met := range f.GetMetric() {
			for _, lp := range met.GetLabel() {
				if lp.GetName() == "tid" && lp.GetValue() == "t-456" {
					t.Errorf("expected no metric for tid=t-456, but found counter=%v",
						met.GetCounter().GetValue())
				}
			}
		}
	}
}
