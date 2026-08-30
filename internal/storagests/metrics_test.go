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
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() != "result" && label.GetName() != "reason" {
					t.Fatalf("unexpected metric label %q in %s", label.GetName(), family.GetName())
				}
				if label.GetValue() != "error" && label.GetValue() != "internal" {
					t.Fatalf("unclosed metric value %q in %s", label.GetValue(), family.GetName())
				}
			}
		}
	}
}
