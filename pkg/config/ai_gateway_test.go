package config

import (
	"strings"
	"testing"
)

func TestAIGatewayDefaultsAndClosedConfiguration(t *testing.T) {
	base := "issuerBaseUrl: https://tikti.example.test\ntenantRuntimeAuthorityV1: true\napiKey: synthetic-test-runtime-key-32bytes\n" + convesteProvidersYAML + "aiGateway:\n  enabled: true\n  authorityUrl: http://code-admin-api.code-admin.svc.cluster.local:8080/internal/v1/ai-gateway/identity:authorize\n"
	cfg, err := LoadConfig(writeTempConfig(t, base))
	if err != nil || !cfg.AIGateway.Enabled || cfg.AIGateway.AccessTokenTTLSeconds != 300 {
		t.Fatalf("bounded AI configuration rejected: %v", err)
	}
	if cfg, err := LoadConfig(writeTempConfig(t, convesteProvidersYAML)); err != nil || cfg.AIGateway.Enabled {
		t.Fatal("AI capability must default off")
	}
	for _, raw := range []string{strings.Replace(base, "http://code-admin-api.code-admin.svc.cluster.local:8080", "http://example.test", 1), strings.Replace(base, "tenantRuntimeAuthorityV1: true", "tenantRuntimeAuthorityV1: false", 1), base + "  accessTokenTtlSeconds: 301\n", base + "  maximumConcurrent: 33\n", base + "  runtime:\n    enabled: true\n", base + "  storeRuntime:\n    enabled: true\n"} {
		if _, err := LoadConfig(writeTempConfig(t, raw)); err == nil {
			t.Fatal("incomplete AI installation authority accepted")
		}
	}
}
