package config

import "testing"

func TestSQLTenantRuntimeAuthorityIndependentDefaultOffConfig(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, `{}`))
	if err != nil || cfg.TenantRuntimeAuthorityV1 {
		t.Fatal("runtime authority must default off")
	}
	cfg, err = LoadConfig(writeTempConfig(t, "tenantRuntimeAuthorityV1: true\napiKey: fixture-key"))
	if err != nil || !cfg.TenantRuntimeAuthorityV1 || cfg.TenantScopedTokenClaimsV1 || cfg.TenantTargetDiscoveryV2 {
		t.Fatal("authority requires an unrelated admission/browser feature")
	}
	t.Setenv("TENANT_RUNTIME_AUTHORITY_V1", "true")
	cfg, err = LoadConfig(writeTempConfig(t, "tenantRuntimeAuthorityV1: false\napiKey: fixture-key"))
	if err != nil || !cfg.TenantRuntimeAuthorityV1 {
		t.Fatal("explicit authority flag ignored")
	}
	for _, value := range []string{"", "TRUE", "1", "invalid"} {
		t.Setenv("TENANT_RUNTIME_AUTHORITY_V1", value)
		if _, err := LoadConfig(writeTempConfig(t, "apiKey: fixture-key")); err == nil {
			t.Fatal("invalid authority flag accepted")
		}
	}
	t.Setenv("TENANT_RUNTIME_AUTHORITY_V1", "true")
	for _, key := range []string{"", "'${API_KEY}'", "' with-space '", "'comma,key'"} {
		if _, err := LoadConfig(writeTempConfig(t, "apiKey: "+key)); err == nil {
			t.Fatal("invalid configured authority credential accepted")
		}
	}
}
