package config

import (
	"fmt"
	"strings"
)

// TrustedWorkloadProvider is one normalized issuer -> clusterRef trust entry.
// ClusterRef is operator configuration and is never read from a token.
type TrustedWorkloadProvider struct {
	ClusterRef string
	Issuer     string
}

// TrustedProviders returns the legacy single issuer (when configured) followed
// by every explicit provider, with surrounding whitespace removed. It performs
// no validation; callers use ValidateTrustedProviderUniqueness.
func (c WorkloadIdentityConfig) TrustedProviders() []TrustedWorkloadProvider {
	providers := make([]TrustedWorkloadProvider, 0, len(c.Providers)+1)
	if issuer := strings.TrimSpace(c.Issuer); issuer != "" {
		providers = append(providers, TrustedWorkloadProvider{ClusterRef: strings.TrimSpace(c.ClusterRef), Issuer: issuer})
	}
	for _, provider := range c.Providers {
		providers = append(providers, TrustedWorkloadProvider{
			ClusterRef: strings.TrimSpace(provider.ClusterRef), Issuer: strings.TrimSpace(provider.Issuer),
		})
	}
	return providers
}

// TrustedClusterRefs returns every non-empty trusted clusterRef in
// configuration order.
func (c WorkloadIdentityConfig) TrustedClusterRefs() []string {
	refs := make([]string, 0, len(c.Providers)+1)
	for _, provider := range c.TrustedProviders() {
		if provider.ClusterRef != "" {
			refs = append(refs, provider.ClusterRef)
		}
	}
	return refs
}

// ValidateTrustedProviderUniqueness refuses any configuration in which an
// issuer, or a non-empty clusterRef, appears more than once across the trusted
// providers. The issuer -> clusterRef map is shared by the workload exchange,
// storage STS and forward-auth, so a duplicate would let one provider silently
// replace another. The check is unconditional (ADR-0022 C3).
func (c WorkloadIdentityConfig) ValidateTrustedProviderUniqueness() error {
	providers := c.TrustedProviders()
	issuers := make(map[string]struct{}, len(providers))
	clusterRefs := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if provider.Issuer == "" {
			return fmt.Errorf("workload identity provider issuer is required")
		}
		if _, duplicate := issuers[provider.Issuer]; duplicate {
			return fmt.Errorf("workload identity provider issuer %q is duplicated", provider.Issuer)
		}
		issuers[provider.Issuer] = struct{}{}
		if provider.ClusterRef == "" {
			continue
		}
		if _, duplicate := clusterRefs[provider.ClusterRef]; duplicate {
			return fmt.Errorf("workload identity provider clusterRef %q is duplicated", provider.ClusterRef)
		}
		clusterRefs[provider.ClusterRef] = struct{}{}
	}
	return nil
}
