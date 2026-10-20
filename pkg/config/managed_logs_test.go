package config

import (
	"strings"
	"testing"
)

func TestManagedLogsConfigDefaultsAndBounds(t *testing.T) {
	valid := "issuerBaseUrl: https://conveste.codefoundry.cc\n" + convesteProvidersYAML + "  managedLogs:\n    enabled: true\n    authorityUrl: http://code-admin-api.code-admin.svc.cluster.local:8080/internal/v1/logs-grants:authorize\n"
	cfg, err := LoadConfig(writeTempConfig(t, valid))
	if err != nil || !cfg.WorkloadIdentity.ManagedLogs.Enabled || cfg.WorkloadIdentity.ManagedLogs.AccessTokenTTLSeconds != 300 {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg, err = LoadConfig(writeTempConfig(t, convesteProvidersYAML)); err != nil || cfg.WorkloadIdentity.ManagedLogs.Enabled {
		t.Fatal("managed Logs must default off")
	}
	for _, body := range []string{
		strings.Replace(valid, "http://code-admin-api.code-admin.svc.cluster.local:8080", "http://outside.example:8080", 1),
		strings.Replace(valid, "logs-grants:authorize", "logs-sources:resolve", 1),
		strings.Replace(valid, "tikti-workload-exchange", "logs-ingest", 1),
		strings.Replace(valid, "https://conveste.codefoundry.cc", "http://conveste.codefoundry.cc", 1),
		strings.Replace(valid, ":8080/", ":0/", 1),
		valid + "    accessTokenTtlSeconds: 301\n", valid + "    dependencyTimeoutSeconds: 11\n", valid + "    maximumConcurrent: 33\n", valid + "    perIdentityPerMinute: 61\n",
	} {
		if _, err = LoadConfig(writeTempConfig(t, body)); err == nil {
			t.Fatal("unsafe Logs startup configuration accepted")
		}
	}
}
