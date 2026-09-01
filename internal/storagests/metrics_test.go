package storagests

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsMapUntrustedValuesToClosedDimensions(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	metrics.observeRequest("tenant-payments", "system:serviceaccount:secret", time.Now())
	metrics.observeAuthorizer("bucket-uid", time.Now())
	metrics.observeMinIO("request-id", time.Now())
	metrics.observeAdmin("tenant-payments", "bucket-uid", "system:serviceaccount:secret", time.Now())
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() != "operation" && label.GetName() != "result" && label.GetName() != "reason" {
					t.Fatalf("unexpected metric label %q in %s", label.GetName(), family.GetName())
				}
				if label.GetValue() != "error" && label.GetValue() != "internal" {
					t.Fatalf("unclosed metric value %q in %s", label.GetValue(), family.GetName())
				}
			}
		}
	}
}

func TestAdminDeleteMetricsExposeOnlyClosedOperationResultAndReason(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	metrics.observeAdmin("delete", "success", "allowed", time.Now())
	metrics.observeAdmin("delete", "error", "object_changed", time.Now())
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "tikti_storage_admin_object_requests_total" {
			continue
		}
		if len(family.Metric) != 2 {
			t.Fatalf("admin request metric series=%d", len(family.Metric))
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "operation" && label.GetValue() != "delete" {
					t.Fatalf("operation=%q", label.GetValue())
				}
				if label.GetName() == "reason" && label.GetValue() != "allowed" && label.GetValue() != "object_changed" {
					t.Fatalf("reason=%q", label.GetValue())
				}
			}
		}
		return
	}
	t.Fatal("administrative object request metric is absent")
}
