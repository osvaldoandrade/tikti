package app

import (
	"strings"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

// ADR-0022 C3: the issuer -> clusterRef map is shared by every workload
// verifier consumer, so a duplicate issuer or clusterRef must never start, even
// when a caller bypasses LoadConfig.
func TestNewWorkloadTokenVerifierRefusesDuplicateTrustedProviders(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.WorkloadIdentityConfig
	}{
		{name: "duplicate issuer", cfg: config.WorkloadIdentityConfig{Audience: "tikti-workload-exchange", JWKSCacheTTLSeconds: 1, Providers: []config.WorkloadIdentityProviderConfig{
			{ClusterRef: "conveste-hostgator", Issuer: "https://kubernetes.default.svc.cluster.local", JWKSURL: "https://k3s-one.example/jwks"},
			{ClusterRef: "other-k3s", Issuer: "https://kubernetes.default.svc.cluster.local", JWKSURL: "https://k3s-two.example/jwks"},
		}}},
		{name: "legacy issuer repeated", cfg: config.WorkloadIdentityConfig{
			Audience: "tikti-workload-exchange", JWKSCacheTTLSeconds: 1,
			Issuer: "https://cluster.example", ClusterRef: "code-cloud", JWKSURL: "https://cluster.example/jwks",
			Providers: []config.WorkloadIdentityProviderConfig{{ClusterRef: "k3s", Issuer: "https://cluster.example", JWKSURL: "https://cluster.example/jwks"}},
		}},
		{name: "duplicate clusterRef", cfg: config.WorkloadIdentityConfig{Audience: "tikti-workload-exchange", JWKSCacheTTLSeconds: 1, Providers: []config.WorkloadIdentityProviderConfig{
			{ClusterRef: "code-cloud", Issuer: "https://one.example", JWKSURL: "https://one.example/jwks"},
			{ClusterRef: "code-cloud", Issuer: "https://two.example", JWKSURL: "https://two.example/jwks"},
		}}},
	}
	for _, test := range tests {
		verifier, err := newWorkloadTokenVerifier(test.cfg)
		if err == nil || verifier != nil || !strings.Contains(err.Error(), "duplicated") {
			t.Fatalf("%s: verifier=%T err=%v", test.name, verifier, err)
		}
	}
}

func TestNewApplicationRefusesDuplicateTrustedProvidersUnconditionally(t *testing.T) {
	server := miniredis.RunT(t)
	cfg := workloadRuntimeConfig("admin-key", applicationTestPrivateKey(t, 2048))
	cfg.RedisAddr = server.Addr()
	cfg.WorkloadIdentity = config.WorkloadIdentityConfig{
		Audience: "tikti-workload-exchange", HTTPTimeoutSeconds: 1, JWKSCacheTTLSeconds: 1,
		Providers: []config.WorkloadIdentityProviderConfig{
			{ClusterRef: "conveste-hostgator", Issuer: "https://kubernetes.default.svc.cluster.local", JWKSURL: "https://k3s.example/jwks"},
			{ClusterRef: "conveste-hostgator", Issuer: "https://other.example", JWKSURL: "https://other.example/jwks"},
		},
	}
	// The CodeQ binding flag is off: uniqueness is still enforced.
	if application, err := NewApplication(cfg); err == nil || application != nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("NewApplication() = %v, %v", application, err)
	}
}

func TestNewWorkloadTokenVerifierAcceptsInstallationProviderShapes(t *testing.T) {
	// Conveste: a pinned file JWKS for the generic K3s issuer plus the GKE MASTER.
	// The Code installation uses gcp authentication, which needs ambient Google
	// credentials, so its uniqueness is covered in pkg/config without a verifier.
	cfg := config.WorkloadIdentityConfig{
		Audience: "tikti-workload-exchange", HTTPTimeoutSeconds: 1, JWKSCacheTTLSeconds: 1,
		Providers: []config.WorkloadIdentityProviderConfig{
			{ClusterRef: "conveste-hostgator", Issuer: "https://kubernetes.default.svc.cluster.local", JWKSURL: "file:///app/etc/workload-jwks/conveste-hostgator.json", Authentication: "none"},
			{ClusterRef: "code-cloud", Issuer: "https://container.googleapis.com/v1/projects/project-9c21a81d-9fb1-477f-8cb/locations/us-central1/clusters/code-cloud", JWKSURL: "https://container.googleapis.com/v1/projects/project-9c21a81d-9fb1-477f-8cb/locations/us-central1/clusters/code-cloud/jwks", Authentication: "none"},
		},
	}
	verifier, err := newWorkloadTokenVerifier(cfg)
	if err != nil || verifier == nil {
		t.Fatalf("Conveste provider shape rejected: %T %v", verifier, err)
	}
}
