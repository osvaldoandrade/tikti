package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// AIMachineIdentity is installation authority, never a tenant request or grant.
type AIMachineIdentity struct {
	Enabled           bool   `yaml:"enabled"`
	Issuer            string `yaml:"issuer"`
	ClusterRef        string `yaml:"clusterRef"`
	Namespace         string `yaml:"namespace"`
	ServiceAccount    string `yaml:"serviceAccount"`
	ServiceAccountUID string `yaml:"serviceAccountUID"`
}

type AIGatewayConfig struct {
	Enabled                  bool              `yaml:"enabled"`
	AuthorityURL             string            `yaml:"authorityUrl"`
	AccessTokenTTLSeconds    int               `yaml:"accessTokenTtlSeconds"`
	DependencyTimeoutSeconds int               `yaml:"dependencyTimeoutSeconds"`
	MaximumConcurrent        int               `yaml:"maximumConcurrent"`
	PerIdentityPerMinute     int               `yaml:"perIdentityPerMinute"`
	InstallationUID          string            `yaml:"installationUID"`
	RuntimeTenantID          string            `yaml:"runtimeTenantId"`
	Runtime                  AIMachineIdentity `yaml:"runtime"`
	StoreAudience            string            `yaml:"storeAudience"`
	StoreRuntime             AIMachineIdentity `yaml:"storeRuntime"`
	StoreBootstrap           AIMachineIdentity `yaml:"storeBootstrap"`
}

func (c *AIGatewayConfig) applyDefaults() {
	if c.AccessTokenTTLSeconds == 0 {
		c.AccessTokenTTLSeconds = 300
	}
	if c.DependencyTimeoutSeconds == 0 {
		c.DependencyTimeoutSeconds = 2
	}
	if c.MaximumConcurrent == 0 {
		c.MaximumConcurrent = 8
	}
	if c.PerIdentityPerMinute == 0 {
		c.PerIdentityPerMinute = 12
	}
}

func (c Config) ValidateAIGateway() error {
	p := c.AIGateway
	if !p.Enabled {
		return nil
	}
	if c.WorkloadIdentity.Audience != "tikti-workload-exchange" || len(c.WorkloadIdentity.TrustedProviders()) == 0 || !validHTTPSOrigin(c.IssuerBaseURL) || !c.TenantRuntimeAuthorityV1 {
		return fmt.Errorf("AI requires trusted workload providers and tenant runtime authority")
	}
	if err := c.WorkloadIdentity.ValidateTrustedProviderUniqueness(); err != nil {
		return err
	}
	if _, err := aigateway.NewClient(p.AuthorityURL, time.Duration(p.DependencyTimeoutSeconds)*time.Second); err != nil {
		return fmt.Errorf("AI authority URL is invalid")
	}
	if p.AccessTokenTTLSeconds < 30 || p.AccessTokenTTLSeconds > 300 || p.MaximumConcurrent < 1 || p.MaximumConcurrent > 32 || p.PerIdentityPerMinute < 1 || p.PerIdentityPerMinute > 60 {
		return fmt.Errorf("AI exchange bounds are invalid")
	}
	for _, identity := range []AIMachineIdentity{p.Runtime, p.StoreRuntime, p.StoreBootstrap} {
		if !identity.Enabled {
			continue
		}
		valid := false
		for _, provider := range c.WorkloadIdentity.TrustedProviders() {
			if provider.Issuer == identity.Issuer && provider.ClusterRef == identity.ClusterRef {
				valid = true
			}
		}
		_, validSubject := domain.ParseWorkloadSubject("system:serviceaccount:" + identity.Namespace + ":" + identity.ServiceAccount)
		if !valid || !validSubject || !domain.ValidWorkloadObjectUID(identity.ServiceAccountUID) || !domain.ValidWorkloadObjectUID(p.InstallationUID) || !validRoleTenantIDConfig(p.RuntimeTenantID) {
			return fmt.Errorf("AI machine installation pins are incomplete")
		}
	}
	if p.StoreRuntime.Enabled || p.StoreBootstrap.Enabled {
		if p.StoreAudience == "" || len(p.StoreAudience) > 128 || strings.TrimSpace(p.StoreAudience) != p.StoreAudience || strings.ContainsAny(p.StoreAudience, " \t\r\n") || p.StoreAudience == "code-admin-logs-store" || p.StoreAudience == aigateway.Audience || p.StoreAudience == aigateway.RuntimeAudience {
			return fmt.Errorf("AI store requires a separate installation audience")
		}
	}
	if p.StoreBootstrap.Enabled && (p.StoreRuntime.Enabled && p.StoreBootstrap.Issuer == p.StoreRuntime.Issuer && p.StoreBootstrap.ServiceAccountUID == p.StoreRuntime.ServiceAccountUID || p.Runtime.Enabled && p.StoreBootstrap.Issuer == p.Runtime.Issuer && p.StoreBootstrap.ServiceAccountUID == p.Runtime.ServiceAccountUID) {
		return fmt.Errorf("AI bootstrap requires a separate installation identity")
	}
	return nil
}

func validRoleTenantIDConfig(value string) bool {
	return value != domain.RetiredDefaultTenantID && domain.ValidWorkloadClusterRef(value)
}
