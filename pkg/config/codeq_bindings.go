package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	// CodeQBindingServiceSubject is the exact sub of the Tikti -> API service
	// assertion (ADR-0022 C2/C3).
	CodeQBindingServiceSubject = "tikti:codeq-binding-exchange"
	// CodeQBindingAuthorityPath is the exact C2 authority route.
	CodeQBindingAuthorityPath = "/internal/v1/codeq-bindings:authorize"

	defaultCodeQBindingAccessTokenTTLSeconds    = 300
	defaultCodeQBindingDependencyTimeoutSeconds = 2
	defaultCodeQBindingMaximumConcurrent        = 8
	defaultCodeQBindingPerIdentityPerMinute     = 6
)

var clusterLocalServiceHost = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\.svc\.cluster\.local$`)

// CodeQBindingsConfig configures the default-off ADR-0022 C3 grant. Every
// authority-bearing value is installation configuration, never request input.
type CodeQBindingsConfig struct {
	Enabled                  bool   `yaml:"enabled"`
	AuthorityURL             string `yaml:"authorityUrl"`
	ServiceSubject           string `yaml:"serviceSubject"`
	AccessTokenTTLSeconds    int    `yaml:"accessTokenTtlSeconds"`
	DependencyTimeoutSeconds int    `yaml:"dependencyTimeoutSeconds"`
	MaximumConcurrent        int    `yaml:"maximumConcurrent"`
	PerIdentityPerMinute     int    `yaml:"perIdentityPerMinute"`
}

func (c *CodeQBindingsConfig) applyDefaults() {
	c.AuthorityURL = strings.TrimSpace(c.AuthorityURL)
	c.ServiceSubject = strings.TrimSpace(c.ServiceSubject)
	if c.ServiceSubject == "" {
		c.ServiceSubject = CodeQBindingServiceSubject
	}
	if c.AccessTokenTTLSeconds == 0 {
		c.AccessTokenTTLSeconds = defaultCodeQBindingAccessTokenTTLSeconds
	}
	if c.DependencyTimeoutSeconds == 0 {
		c.DependencyTimeoutSeconds = defaultCodeQBindingDependencyTimeoutSeconds
	}
	if c.MaximumConcurrent == 0 {
		c.MaximumConcurrent = defaultCodeQBindingMaximumConcurrent
	}
	if c.PerIdentityPerMinute == 0 {
		c.PerIdentityPerMinute = defaultCodeQBindingPerIdentityPerMinute
	}
}

// ValidateCodeQBindings enforces the ADR-0022 C3 startup refusals when the
// grant is enabled. It never contacts authorityUrl.
func (c Config) ValidateCodeQBindings() error {
	bindings := c.WorkloadIdentity.CodeQBindings
	if !bindings.Enabled {
		return nil
	}
	providers := c.WorkloadIdentity.TrustedProviders()
	if len(providers) == 0 {
		return fmt.Errorf("workloadIdentity.codeqBindings requires at least one trusted workload provider")
	}
	for _, provider := range providers {
		if provider.ClusterRef == "" || !validClusterRef(provider.ClusterRef) {
			return fmt.Errorf("workloadIdentity.codeqBindings requires a clusterRef for every trusted provider")
		}
	}
	if err := c.WorkloadIdentity.ValidateTrustedProviderUniqueness(); err != nil {
		return err
	}
	if strings.TrimSpace(c.WorkloadIdentity.Audience) != "tikti-workload-exchange" {
		return fmt.Errorf("workloadIdentity.codeqBindings requires the tikti-workload-exchange subject audience")
	}
	if !ValidCodeQBindingAuthorityURL(bindings.AuthorityURL) {
		return fmt.Errorf("workloadIdentity.codeqBindings.authorityUrl must be http://<svc>.<ns>.svc.cluster.local:<port>%s or HTTPS", CodeQBindingAuthorityPath)
	}
	if bindings.ServiceSubject != CodeQBindingServiceSubject {
		return fmt.Errorf("workloadIdentity.codeqBindings.serviceSubject must equal %s", CodeQBindingServiceSubject)
	}
	if bindings.AccessTokenTTLSeconds < 30 || bindings.AccessTokenTTLSeconds > 300 {
		return fmt.Errorf("workloadIdentity.codeqBindings.accessTokenTtlSeconds must be between 30 and 300")
	}
	if bindings.DependencyTimeoutSeconds < 1 || bindings.DependencyTimeoutSeconds > 10 {
		return fmt.Errorf("workloadIdentity.codeqBindings.dependencyTimeoutSeconds must be between 1 and 10")
	}
	if bindings.MaximumConcurrent < 1 || bindings.MaximumConcurrent > 32 {
		return fmt.Errorf("workloadIdentity.codeqBindings.maximumConcurrent must be between 1 and 32")
	}
	if bindings.PerIdentityPerMinute < 1 || bindings.PerIdentityPerMinute > 60 {
		return fmt.Errorf("workloadIdentity.codeqBindings.perIdentityPerMinute must be between 1 and 60")
	}
	if !validHTTPSOrigin(c.IssuerBaseURL) {
		return fmt.Errorf("workloadIdentity.codeqBindings requires issuerBaseUrl to be one exact HTTPS origin")
	}
	return nil
}

// ValidCodeQBindingAuthorityURL accepts exactly the C3 authority URL forms:
// in-cluster HTTP to <svc>.<ns>.svc.cluster.local with an explicit port, or
// HTTPS, both with the exact authority path and no credentials, query or
// fragment.
func ValidCodeQBindingAuthorityURL(raw string) bool {
	if raw != strings.TrimSpace(raw) || raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Host == "" ||
		parsed.EscapedPath() != CodeQBindingAuthorityPath {
		return false
	}
	switch parsed.Scheme {
	case "https":
		return parsed.Hostname() != ""
	case "http":
		port, err := strconv.Atoi(parsed.Port())
		return err == nil && port >= 1 && port <= 65535 && clusterLocalServiceHost.MatchString(parsed.Hostname())
	default:
		return false
	}
}
