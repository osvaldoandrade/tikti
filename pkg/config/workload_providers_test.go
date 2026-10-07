package config

import (
	"slices"
	"strings"
	"testing"
)

// The provider lists below mirror the two live installations (ADR-0022 C3):
// Conveste primary-tikti.json and Code control-plane/tikti.json.
const convesteProvidersYAML = `
workloadIdentity:
  audience: tikti-workload-exchange
  providers:
    - clusterRef: conveste-hostgator
      issuer: https://kubernetes.default.svc.cluster.local
      jwksUrl: file:///app/etc/workload-jwks/conveste-hostgator.json
      authentication: none
    - clusterRef: code-cloud
      issuer: https://container.googleapis.com/v1/projects/project-9c21a81d-9fb1-477f-8cb/locations/us-central1/clusters/code-cloud
      jwksUrl: https://container.googleapis.com/v1/projects/project-9c21a81d-9fb1-477f-8cb/locations/us-central1/clusters/code-cloud/jwks
      authentication: none
`

const codeProvidersYAML = `
workloadIdentity:
  audience: tikti-workload-exchange
  providers:
    - clusterRef: code-cloud-acceptance
      issuer: https://container.googleapis.com/v1/projects/code-company-admin-prod/locations/us-central1/clusters/code-admin-prod-cluster
      jwksUrl: https://gke-bfa6f8f9be064004ba74c8bf00b57806e327-1043885273992.us-central1.gke.goog/openid/v1/jwks
      authentication: gcp
    - clusterRef: itransform-cluster
      issuer: https://container.googleapis.com/v1/projects/itransform-cloud/locations/us-central1-a/clusters/itransform-cluster
      jwksUrl: https://gke-2a781cbe7a6644e3ae9f9fb45fb9979fa809-407380153421.us-central1-a.gke.goog/openid/v1/jwks
      authentication: gcp
`

func TestWorkloadProviderUniquenessAcceptsBothInstallations(t *testing.T) {
	for name, body := range map[string]string{"conveste": convesteProvidersYAML, "code": codeProvidersYAML} {
		cfg, err := LoadConfig(writeTempConfig(t, body))
		if err != nil {
			t.Fatalf("%s installation providers rejected: %v", name, err)
		}
		if err := cfg.WorkloadIdentity.ValidateTrustedProviderUniqueness(); err != nil {
			t.Fatalf("%s uniqueness: %v", name, err)
		}
		if refs := cfg.WorkloadIdentity.TrustedClusterRefs(); len(refs) != 2 {
			t.Fatalf("%s trusted clusterRefs = %v", name, refs)
		}
	}
}

func TestWorkloadProviderUniquenessRefusesDuplicates(t *testing.T) {
	tests := []struct {
		name string
		cfg  WorkloadIdentityConfig
		want string
	}{
		{name: "duplicate provider issuer", cfg: WorkloadIdentityConfig{Providers: []WorkloadIdentityProviderConfig{
			{ClusterRef: "conveste-hostgator", Issuer: "https://kubernetes.default.svc.cluster.local"},
			{ClusterRef: "other-k3s", Issuer: "https://kubernetes.default.svc.cluster.local"},
		}}, want: "issuer"},
		{name: "duplicate issuer after trimming", cfg: WorkloadIdentityConfig{Providers: []WorkloadIdentityProviderConfig{
			{ClusterRef: "a", Issuer: "https://issuer.example"},
			{ClusterRef: "b", Issuer: " https://issuer.example "},
		}}, want: "issuer"},
		{name: "legacy issuer repeated by provider", cfg: WorkloadIdentityConfig{
			Issuer: "https://issuer.example", ClusterRef: "a",
			Providers: []WorkloadIdentityProviderConfig{{ClusterRef: "b", Issuer: "https://issuer.example"}},
		}, want: "issuer"},
		{name: "duplicate provider clusterRef", cfg: WorkloadIdentityConfig{Providers: []WorkloadIdentityProviderConfig{
			{ClusterRef: "code-cloud", Issuer: "https://one.example"},
			{ClusterRef: "code-cloud", Issuer: "https://two.example"},
		}}, want: "clusterRef"},
		{name: "legacy clusterRef repeated by provider", cfg: WorkloadIdentityConfig{
			Issuer: "https://one.example", ClusterRef: "code-cloud",
			Providers: []WorkloadIdentityProviderConfig{{ClusterRef: "code-cloud", Issuer: "https://two.example"}},
		}, want: "clusterRef"},
		{name: "empty provider issuer", cfg: WorkloadIdentityConfig{Providers: []WorkloadIdentityProviderConfig{
			{ClusterRef: "a", Issuer: " "},
		}}, want: "issuer"},
	}
	for _, test := range tests {
		err := test.cfg.ValidateTrustedProviderUniqueness()
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s: error = %v, want mention of %q", test.name, err, test.want)
		}
	}
	// Empty clusterRefs are not a trust key and may repeat; only issuers must be unique.
	unscoped := WorkloadIdentityConfig{Providers: []WorkloadIdentityProviderConfig{
		{Issuer: "https://one.example"}, {Issuer: "https://two.example"},
	}}
	if err := unscoped.ValidateTrustedProviderUniqueness(); err != nil {
		t.Fatalf("distinct issuers without clusterRefs rejected: %v", err)
	}
	if refs := unscoped.TrustedClusterRefs(); len(refs) != 0 {
		t.Fatalf("empty clusterRefs reported as trusted: %v", refs)
	}
}

func TestLoadConfigRefusesDuplicateLegacyAndProviderIssuer(t *testing.T) {
	body := `
workloadIdentity:
  clusterRef: code-cloud
  issuer: https://kubernetes.default.svc.cluster.local
  jwksUrl: https://kubernetes.default.svc.cluster.local/openid/v1/jwks
  providers:
    - clusterRef: conveste-hostgator
      issuer: https://kubernetes.default.svc.cluster.local
      jwksUrl: file:///app/etc/workload-jwks/conveste-hostgator.json
`
	if _, err := LoadConfig(writeTempConfig(t, body)); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("LoadConfig() duplicate issuer error = %v", err)
	}
}

func TestTrustedProvidersOrderAndNormalization(t *testing.T) {
	cfg := WorkloadIdentityConfig{
		Issuer: " https://legacy.example ", ClusterRef: " legacy ",
		Providers: []WorkloadIdentityProviderConfig{{ClusterRef: " k3s ", Issuer: " https://k3s.example "}},
	}
	got := cfg.TrustedProviders()
	want := []TrustedWorkloadProvider{{ClusterRef: "legacy", Issuer: "https://legacy.example"}, {ClusterRef: "k3s", Issuer: "https://k3s.example"}}
	if !slices.Equal(got, want) {
		t.Fatalf("TrustedProviders() = %#v", got)
	}
}
