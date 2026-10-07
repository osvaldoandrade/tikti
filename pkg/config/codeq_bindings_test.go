package config

import (
	"strings"
	"testing"
)

func withCodeQBindings(providers, bindings string) string {
	return "issuerBaseUrl: https://conveste.codefoundry.cc\n" + providers + bindings
}

func TestLoadConfigCodeQBindingsDefaultsOff(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, convesteProvidersYAML))
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.WorkloadIdentity.CodeQBindings
	want := CodeQBindingsConfig{
		ServiceSubject: CodeQBindingServiceSubject, AccessTokenTTLSeconds: 300,
		DependencyTimeoutSeconds: 2, MaximumConcurrent: 8, PerIdentityPerMinute: 6,
	}
	if got != want {
		t.Fatalf("defaults = %#v, want %#v", got, want)
	}
	// Disabled values are not interpreted, so a disabled block never blocks startup.
	disabled := convesteProvidersYAML + "  codeqBindings:\n    enabled: false\n    authorityUrl: not-a-url\n"
	if _, err := LoadConfig(writeTempConfig(t, disabled)); err != nil {
		t.Fatalf("disabled block rejected: %v", err)
	}
}

func TestLoadConfigCodeQBindingsEnabledForBothInstallations(t *testing.T) {
	block := "  codeqBindings:\n    enabled: true\n    authorityUrl: http://code-admin-api.code-admin.svc.cluster.local:8080/internal/v1/codeq-bindings:authorize\n"
	for name, providers := range map[string]string{"conveste": convesteProvidersYAML, "code": codeProvidersYAML} {
		cfg, err := LoadConfig(writeTempConfig(t, withCodeQBindings(providers, block)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !cfg.WorkloadIdentity.CodeQBindings.Enabled || cfg.WorkloadIdentity.CodeQBindings.ServiceSubject != CodeQBindingServiceSubject {
			t.Fatalf("%s: %#v", name, cfg.WorkloadIdentity.CodeQBindings)
		}
	}
}

func TestLoadConfigCodeQBindingsStartupRefusals(t *testing.T) {
	valid := "    authorityUrl: http://code-admin-api.code-admin.svc.cluster.local:8080/internal/v1/codeq-bindings:authorize\n"
	tests := []struct {
		name   string
		body   string
		reason string
	}{
		{name: "legacy issuer without clusterRef", body: "issuerBaseUrl: https://conveste.codefoundry.cc\nworkloadIdentity:\n  issuer: https://kubernetes.example\n  jwksUrl: https://kubernetes.example/jwks\n  codeqBindings:\n    enabled: true\n" + valid, reason: "clusterRef for every trusted provider"},
		{name: "no providers", body: "issuerBaseUrl: https://conveste.codefoundry.cc\nworkloadIdentity:\n  codeqBindings:\n    enabled: true\n" + valid, reason: "at least one trusted workload provider"},
		{name: "missing authorityUrl", body: withCodeQBindings(convesteProvidersYAML, "  codeqBindings:\n    enabled: true\n"), reason: "authorityUrl"},
		{name: "wrong service subject", body: withCodeQBindings(convesteProvidersYAML, "  codeqBindings:\n    enabled: true\n"+valid+"    serviceSubject: tikti:object-storage-sts\n"), reason: "serviceSubject"},
		{name: "ttl above 300", body: withCodeQBindings(convesteProvidersYAML, "  codeqBindings:\n    enabled: true\n"+valid+"    accessTokenTtlSeconds: 301\n"), reason: "accessTokenTtlSeconds"},
		{name: "ttl below 30", body: withCodeQBindings(convesteProvidersYAML, "  codeqBindings:\n    enabled: true\n"+valid+"    accessTokenTtlSeconds: 29\n"), reason: "accessTokenTtlSeconds"},
		{name: "timeout above 10", body: withCodeQBindings(convesteProvidersYAML, "  codeqBindings:\n    enabled: true\n"+valid+"    dependencyTimeoutSeconds: 11\n"), reason: "dependencyTimeoutSeconds"},
		{name: "concurrency above 32", body: withCodeQBindings(convesteProvidersYAML, "  codeqBindings:\n    enabled: true\n"+valid+"    maximumConcurrent: 33\n"), reason: "maximumConcurrent"},
		{name: "negative rate", body: withCodeQBindings(convesteProvidersYAML, "  codeqBindings:\n    enabled: true\n"+valid+"    perIdentityPerMinute: -1\n"), reason: "perIdentityPerMinute"},
		{name: "http issuer", body: strings.Replace(withCodeQBindings(convesteProvidersYAML, "  codeqBindings:\n    enabled: true\n"+valid), "https://conveste.codefoundry.cc", "http://tikti.local", 1), reason: "issuerBaseUrl"},
		{name: "wrong subject audience", body: withCodeQBindings(strings.Replace(convesteProvidersYAML, "audience: tikti-workload-exchange", "audience: other", 1), "  codeqBindings:\n    enabled: true\n"+valid), reason: "tikti-workload-exchange"},
	}
	for _, test := range tests {
		_, err := LoadConfig(writeTempConfig(t, test.body))
		if err == nil || !strings.Contains(err.Error(), test.reason) {
			t.Fatalf("%s: error = %v, want %q", test.name, err, test.reason)
		}
	}
}

func TestValidCodeQBindingAuthorityURL(t *testing.T) {
	for _, valid := range []string{
		"http://code-admin-api.code-admin.svc.cluster.local:8080/internal/v1/codeq-bindings:authorize",
		"http://api.ns.svc.cluster.local:80/internal/v1/codeq-bindings:authorize",
		"https://code-admin-api.code-admin.svc.cluster.local/internal/v1/codeq-bindings:authorize",
		"https://api.internal.example:8443/internal/v1/codeq-bindings:authorize",
	} {
		if !ValidCodeQBindingAuthorityURL(valid) {
			t.Fatalf("valid URL rejected: %s", valid)
		}
	}
	for _, invalid := range []string{
		"",
		" http://api.ns.svc.cluster.local:8080/internal/v1/codeq-bindings:authorize",
		"http://api.ns.svc.cluster.local/internal/v1/codeq-bindings:authorize",
		"http://api.svc.cluster.local:8080/internal/v1/codeq-bindings:authorize",
		"http://api.ns.svc:8080/internal/v1/codeq-bindings:authorize",
		"http://localhost:8080/internal/v1/codeq-bindings:authorize",
		"http://10.0.0.1:8080/internal/v1/codeq-bindings:authorize",
		"http://api.ns.svc.cluster.local:0/internal/v1/codeq-bindings:authorize",
		"http://api.ns.svc.cluster.local:8080/internal/v1/object-storage:authorize",
		"http://api.ns.svc.cluster.local:8080/internal/v1/codeq-bindings:authorize/",
		"http://api.ns.svc.cluster.local:8080/internal/v1/codeq-bindings:authorize?x=1",
		"http://api.ns.svc.cluster.local:8080/internal/v1/codeq-bindings:authorize#f",
		"https://user:pass@api.example/internal/v1/codeq-bindings:authorize",
		"ftp://api.example/internal/v1/codeq-bindings:authorize",
		"https:///internal/v1/codeq-bindings:authorize",
	} {
		if ValidCodeQBindingAuthorityURL(invalid) {
			t.Fatalf("invalid URL accepted: %q", invalid)
		}
	}
}
