package config

import (
	"strings"
	"testing"
)

func aiValidMachineConfig(t *testing.T) Config {
	t.Helper()
	base := "issuerBaseUrl: https://tikti.example.test\ntenantRuntimeAuthorityV1: true\napiKey: synthetic-test-runtime-key-32bytes\n" + convesteProvidersYAML + "aiGateway:\n  enabled: true\n  authorityUrl: http://code-admin-api.code-admin.svc.cluster.local:8080/internal/v1/ai-gateway/identity:authorize\n"
	c, err := LoadConfig(writeTempConfig(t, base))
	if err != nil {
		t.Fatal(err)
	}
	p := c.WorkloadIdentity.TrustedProviders()[0]
	c.AIGateway.InstallationUID, c.AIGateway.RuntimeTenantID, c.AIGateway.StoreAudience = "installation-1", "payments", "ai-private-store"
	c.AIGateway.Runtime = AIMachineIdentity{Enabled: true, Issuer: p.Issuer, ClusterRef: p.ClusterRef, Namespace: "code-admin", ServiceAccount: "code-admin-ai-gateway", ServiceAccountUID: "runtime-1"}
	c.AIGateway.StoreRuntime = c.AIGateway.Runtime
	c.AIGateway.StoreBootstrap = c.AIGateway.Runtime
	c.AIGateway.StoreBootstrap.ServiceAccount, c.AIGateway.StoreBootstrap.ServiceAccountUID = "ai-bootstrap", "bootstrap-1"
	if err := c.ValidateAIGateway(); err != nil {
		t.Fatalf("valid machine configuration: %v", err)
	}
	return *c
}

func TestAIGatewayMachineConfigurationDoesNotBroadenAuthority(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"workload audience", func(c *Config) { c.WorkloadIdentity.Audience = "other" }},
		{"issuer origin", func(c *Config) { c.IssuerBaseURL = "http://tikti.example.test" }},
		{"tenant authority disabled", func(c *Config) { c.TenantRuntimeAuthorityV1 = false }},
		{"untrusted issuer", func(c *Config) { c.AIGateway.Runtime.Issuer = "https://other.example" }},
		{"untrusted cluster", func(c *Config) { c.AIGateway.Runtime.ClusterRef = "other" }},
		{"invalid namespace", func(c *Config) { c.AIGateway.Runtime.Namespace = "bad:namespace" }},
		{"invalid service account", func(c *Config) { c.AIGateway.Runtime.ServiceAccount = "" }},
		{"missing service account uid", func(c *Config) { c.AIGateway.Runtime.ServiceAccountUID = "" }},
		{"missing installation", func(c *Config) { c.AIGateway.InstallationUID = "" }},
		{"retired tenant", func(c *Config) { c.AIGateway.RuntimeTenantID = "default" }},
		{"invalid tenant", func(c *Config) { c.AIGateway.RuntimeTenantID = "bad:tenant" }},
		{"short ttl", func(c *Config) { c.AIGateway.AccessTokenTTLSeconds = 29 }},
		{"long ttl", func(c *Config) { c.AIGateway.AccessTokenTTLSeconds = 301 }},
		{"zero slots", func(c *Config) { c.AIGateway.MaximumConcurrent = 0 }},
		{"excess slots", func(c *Config) { c.AIGateway.MaximumConcurrent = 33 }},
		{"zero rate", func(c *Config) { c.AIGateway.PerIdentityPerMinute = 0 }},
		{"excess rate", func(c *Config) { c.AIGateway.PerIdentityPerMinute = 61 }},
		{"bootstrap equals runtime", func(c *Config) { c.AIGateway.StoreBootstrap = c.AIGateway.Runtime }},
		{"bootstrap equals store runtime", func(c *Config) {
			c.AIGateway.Runtime.Enabled = false
			c.AIGateway.StoreBootstrap = c.AIGateway.StoreRuntime
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := aiValidMachineConfig(t)
			tc.edit(&c)
			if err := c.ValidateAIGateway(); err == nil {
				t.Fatal("invalid installation authority accepted")
			}
		})
	}
	for _, audience := range []string{"", "code-admin-logs-store", "code-admin-api", "code-llm-service", "other store", " leading", "trailing ", strings.Repeat("a", 129)} {
		c := aiValidMachineConfig(t)
		c.AIGateway.StoreAudience = audience
		if err := c.ValidateAIGateway(); err == nil {
			t.Fatal("shared or ambiguous store audience accepted")
		}
	}
	for _, selected := range []string{"runtime", "store runtime", "bootstrap"} {
		c := aiValidMachineConfig(t)
		runtime, store, bootstrap := c.AIGateway.Runtime, c.AIGateway.StoreRuntime, c.AIGateway.StoreBootstrap
		c.AIGateway.Runtime.Enabled = false
		c.AIGateway.StoreRuntime.Enabled = false
		c.AIGateway.StoreBootstrap.Enabled = false
		switch selected {
		case "runtime":
			c.AIGateway.Runtime = runtime
		case "store runtime":
			c.AIGateway.StoreRuntime = store
		case "bootstrap":
			c.AIGateway.StoreBootstrap = bootstrap
		}
		if err := c.ValidateAIGateway(); err != nil {
			t.Fatalf("separate %s capability rejected: %v", selected, err)
		}
	}
}
