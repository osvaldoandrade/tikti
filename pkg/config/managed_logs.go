package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ManagedLogsConfig gates only the ADR-0023 platform Logs grants. It never
// broadens legacy workload audiences or takes a credential from configuration.
type ManagedLogsConfig struct {
	Enabled                  bool   `yaml:"enabled"`
	AuthorityURL             string `yaml:"authorityUrl"`
	AccessTokenTTLSeconds    int    `yaml:"accessTokenTtlSeconds"`
	DependencyTimeoutSeconds int    `yaml:"dependencyTimeoutSeconds"`
	MaximumConcurrent        int    `yaml:"maximumConcurrent"`
	PerIdentityPerMinute     int    `yaml:"perIdentityPerMinute"`
}

func (c *ManagedLogsConfig) applyDefaults() {
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

func (c Config) ValidateManagedLogs() error {
	p := c.WorkloadIdentity.ManagedLogs
	if !p.Enabled {
		return nil
	}
	if c.WorkloadIdentity.Audience != "tikti-workload-exchange" || len(c.WorkloadIdentity.TrustedProviders()) == 0 || !validHTTPSOrigin(c.IssuerBaseURL) {
		return fmt.Errorf("managed Logs requires trusted workload providers, exact subject audience and HTTPS issuer")
	}
	if err := c.WorkloadIdentity.ValidateTrustedProviderUniqueness(); err != nil {
		return err
	}
	for _, provider := range c.WorkloadIdentity.TrustedProviders() {
		if !validClusterRef(provider.ClusterRef) {
			return fmt.Errorf("managed Logs requires a clusterRef for every provider")
		}
	}
	u, err := url.Parse(p.AuthorityURL)
	if err != nil || p.AuthorityURL != strings.TrimSpace(p.AuthorityURL) || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != "/internal/v1/logs-grants:authorize" {
		return fmt.Errorf("managed Logs authorityUrl is invalid")
	}
	if u.Scheme != "https" {
		port, err := strconv.Atoi(u.Port())
		if u.Scheme != "http" || err != nil || port < 1 || port > 65535 || !clusterLocalServiceHost.MatchString(u.Hostname()) {
			return fmt.Errorf("managed Logs authorityUrl must use HTTPS or an exact cluster service")
		}
	}
	if p.AccessTokenTTLSeconds < 30 || p.AccessTokenTTLSeconds > 300 || p.DependencyTimeoutSeconds < 1 || p.DependencyTimeoutSeconds > 10 || p.MaximumConcurrent < 1 || p.MaximumConcurrent > 32 || p.PerIdentityPerMinute < 1 || p.PerIdentityPerMinute > 60 {
		return fmt.Errorf("managed Logs exchange bounds are invalid")
	}
	return nil
}
