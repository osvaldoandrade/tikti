package config

import (
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config captures runtime parameters loaded from YAML or the environment.
type Config struct {
	Port                               int                    `yaml:"port"`
	RedisAddr                          string                 `yaml:"redisAddr"`
	RedisHost                          string                 `yaml:"redisHost"`
	RedisPort                          int                    `yaml:"redisPort"`
	RedisDB                            int                    `yaml:"redisDb"`
	RedisPassword                      string                 `yaml:"redisPassword"`
	RedisURL                           string                 `yaml:"redisUrl"`
	JwtSecret                          string                 `yaml:"jwtSecret"`
	ApiKey                             string                 `yaml:"apiKey"`
	IssuerBaseURL                      string                 `yaml:"issuerBaseUrl"`
	DefaultAudience                    string                 `yaml:"defaultAudience"`
	JwksPrivateKey                     string                 `yaml:"jwksPrivateKey"`
	JwksKeyID                          string                 `yaml:"jwksKeyId"`
	WorkloadIdentity                   WorkloadIdentityConfig `yaml:"workloadIdentity"`
	SAML                               SAMLConfig             `yaml:"saml"`
	HTTP                               HTTPConfig             `yaml:"http"`
	ForwardAuth                        ForwardAuthConfig      `yaml:"forwardAuth"`
	TenantScopedTokenClaimsV1          bool                   `yaml:"tenantScopedTokenClaimsV1"`
	TenantScopedTokenClaimsV1Tenants   []string               `yaml:"tenantScopedTokenClaimsV1Tenants"`
	ExactMembershipReadRoutesV1        bool                   `yaml:"exactMembershipReadRoutesV1"`
	ExactMembershipReadRoutesV1Tenants []string               `yaml:"exactMembershipReadRoutesV1Tenants"`
	ExactMembershipPageTokenSecret     string                 `yaml:"-"`
	MembershipV2WriteRoutesV1          bool                   `yaml:"membershipV2WriteRoutesV1"`
	MembershipV2WriteRoutesV1Tenants   []string               `yaml:"membershipV2WriteRoutesV1Tenants"`
}

// HTTPConfig defines the public server boundary.
type HTTPConfig struct {
	AllowedOrigins           []string `yaml:"allowedOrigins"`
	ReadHeaderTimeoutSeconds int      `yaml:"readHeaderTimeoutSeconds"`
	ReadTimeoutSeconds       int      `yaml:"readTimeoutSeconds"`
	WriteTimeoutSeconds      int      `yaml:"writeTimeoutSeconds"`
	IdleTimeoutSeconds       int      `yaml:"idleTimeoutSeconds"`
	MaxHeaderBytes           int      `yaml:"maxHeaderBytes"`
}

// ForwardAuthConfig defines credentials accepted only by the edge
// authentication endpoint.
type ForwardAuthConfig struct {
	AccessCookieName string `yaml:"accessCookieName"`
}

// WorkloadIdentityConfig validates Kubernetes projected ServiceAccount tokens
// and controls the short-lived access tokens issued to bound controllers.
type WorkloadIdentityConfig struct {
	Issuer                string                           `yaml:"issuer"`
	Audience              string                           `yaml:"audience"`
	JWKSURL               string                           `yaml:"jwksUrl"`
	JWKSBearerTokenFile   string                           `yaml:"jwksBearerTokenFile"`
	Providers             []WorkloadIdentityProviderConfig `yaml:"providers"`
	HTTPTimeoutSeconds    int                              `yaml:"httpTimeoutSeconds"`
	JWKSCacheTTLSeconds   int                              `yaml:"jwksCacheTtlSeconds"`
	AccessTokenTTLSeconds int                              `yaml:"accessTokenTtlSeconds"`
}

// WorkloadIdentityProviderConfig declares one trusted Kubernetes token issuer.
// ClusterRef is an operator-facing identifier and is not trusted as a claim.
type WorkloadIdentityProviderConfig struct {
	ClusterRef          string `yaml:"clusterRef"`
	Issuer              string `yaml:"issuer"`
	JWKSURL             string `yaml:"jwksUrl"`
	JWKSBearerTokenFile string `yaml:"jwksBearerTokenFile"`
	Authentication      string `yaml:"authentication"`
}

// SAMLConfig holds top-level SAML integration settings.
type SAMLConfig struct {
	Enabled  bool             `yaml:"enabled"`
	SP       SPConfig         `yaml:"sp"`
	ACS      ACSConfig        `yaml:"acs"`
	IdP      IdPSectionConfig `yaml:"idp"`
	Discover DiscoverConfig   `yaml:"discover"`
	Metrics  MetricsConfig    `yaml:"metrics"`
}

// SPConfig holds SAML Service Provider parameters.
type SPConfig struct {
	EntityID                  string        `yaml:"entityID"`
	ACSURL                    string        `yaml:"acsURL"`
	SLOURL                    string        `yaml:"sloURL"`
	SigningKeyPath            string        `yaml:"signingKeyPath"`
	SigningCertPath           string        `yaml:"signingCertPath"`
	EncryptionKeyPath         string        `yaml:"encryptionKeyPath"`
	EncryptionCertPath        string        `yaml:"encryptionCertPath"`
	KeyBits                   int           `yaml:"keyBits"`
	ClockSkew                 time.Duration `yaml:"-"`
	RequestTTL                time.Duration `yaml:"-"`
	AllowedSigAlgs            []string      `yaml:"allowedSigAlgs"`
	AllowedDigestAlgs         []string      `yaml:"allowedDigestAlgs"`
	Canonicalization          string        `yaml:"canonicalization"`
	WatchFile                 bool          `yaml:"watchFile"`
	RequireAssertionSigned    bool          `yaml:"requireAssertionSigned"`
	RequireEncryptedAssertion bool          `yaml:"requireEncryptedAssertion"`
}

// UnmarshalYAML converts clockSkewSeconds and requestTTLSeconds from integer
// seconds into time.Duration values.
func (s *SPConfig) UnmarshalYAML(value *yaml.Node) error {
	type raw SPConfig // prevent recursion
	var aux struct {
		raw           `yaml:",inline"`
		ClockSkewSec  int `yaml:"clockSkewSeconds"`
		RequestTTLSec int `yaml:"requestTTLSeconds"`
	}
	if err := value.Decode(&aux); err != nil {
		return err
	}
	*s = SPConfig(aux.raw)
	s.ClockSkew = time.Duration(aux.ClockSkewSec) * time.Second
	s.RequestTTL = time.Duration(aux.RequestTTLSec) * time.Second
	return nil
}

// ACSConfig holds Assertion Consumer Service settings.
type ACSConfig struct {
	DeliveryMode   string `yaml:"deliveryMode"`
	CookieName     string `yaml:"cookieName"`
	CookieDomain   string `yaml:"cookieDomain"`
	CookieSameSite string `yaml:"cookieSameSite"`
	CookieSecure   bool   `yaml:"cookieSecure"`
	CookieHTTPOnly bool   `yaml:"cookieHTTPOnly"`
	SessionTTL     int    `yaml:"sessionTTL"`
	PostLoginURL   string `yaml:"postLoginURL"`
}

// IdPSectionConfig holds Identity Provider settings.
type IdPSectionConfig struct {
	MetadataURL        string        `yaml:"metadataURL"`
	MetadataPath       string        `yaml:"metadataPath"`
	RefreshInterval    time.Duration `yaml:"-"`
	TrustedCertPaths   []string      `yaml:"trustedCertPaths"`
	SkipSignatureCheck bool          `yaml:"skipSignatureCheck"`
}

// UnmarshalYAML converts refreshIntervalHours from integer hours into a
// time.Duration value.
func (i *IdPSectionConfig) UnmarshalYAML(value *yaml.Node) error {
	type raw IdPSectionConfig // prevent recursion
	var aux struct {
		raw                  `yaml:",inline"`
		RefreshIntervalHours int `yaml:"refreshIntervalHours"`
	}
	if err := value.Decode(&aux); err != nil {
		return err
	}
	*i = IdPSectionConfig(aux.raw)
	i.RefreshInterval = time.Duration(aux.RefreshIntervalHours) * time.Hour
	return nil
}

// DiscoverConfig holds IdP discovery settings.
type DiscoverConfig struct {
	Enabled      bool   `yaml:"enabled"`
	ProtocolType string `yaml:"protocolType"`
	ServiceURL   string `yaml:"serviceURL"`
}

// MetricsConfig holds SAML metrics settings.
type MetricsConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Namespace string `yaml:"namespace"`
}

// Validate checks SAMLConfig invariants. When SAML is enabled the SP must
// provide signing key/cert paths, entityID, and acsURL.
func (s SAMLConfig) Validate() error {
	if !s.Enabled {
		return nil
	}
	if s.SP.SigningKeyPath == "" {
		return fmt.Errorf("saml: signingKeyPath is required when SAML is enabled")
	}
	if s.SP.SigningCertPath == "" {
		return fmt.Errorf("saml: signingCertPath is required when SAML is enabled")
	}
	if s.SP.EntityID == "" {
		return fmt.Errorf("saml: entityID is required when SAML is enabled")
	}
	if s.SP.ACSURL == "" {
		return fmt.Errorf("saml: acsURL is required when SAML is enabled")
	}
	return nil
}

// LoadConfig reads a YAML file, expands environment variables, and returns Config defaults.
func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	expanded := os.Expand(string(data), func(key string) string {
		if val, ok := os.LookupEnv(key); ok {
			return val
		}
		return "${" + key + "}"
	})
	data = []byte(expanded)

	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	for _, secret := range []struct {
		env    string
		target *string
	}{
		{env: "JWT_SECRET_FILE", target: &c.JwtSecret},
		{env: "API_KEY_FILE", target: &c.ApiKey},
		{env: "REDIS_PASSWORD_FILE", target: &c.RedisPassword},
		{env: "JWKS_PRIVATE_KEY_FILE", target: &c.JwksPrivateKey},
	} {
		if err := loadSecretFile(secret.env, secret.target); err != nil {
			return nil, err
		}
	}
	if c.Port == 0 {
		c.Port = 8080
	}
	if c.RedisAddr == "" {
		c.RedisAddr = "localhost:6379"
	}
	if c.RedisHost == "" {
		c.RedisHost = "localhost"
	}
	if c.RedisPort == 0 {
		c.RedisPort = 6379
	}
	if c.RedisDB < 0 {
		c.RedisDB = 0
	}
	if c.JwtSecret == "" {
		c.JwtSecret = "supersecret"
	}
	if c.ApiKey == "" {
		log.Println("WARNING: No API key set.")
	}
	if v := os.Getenv("ISSUER_BASE_URL"); v != "" {
		c.IssuerBaseURL = v
	}
	if v := os.Getenv("DEFAULT_AUDIENCE"); v != "" {
		c.DefaultAudience = v
	}
	if v := os.Getenv("JWKS_PRIVATE_KEY"); v != "" {
		c.JwksPrivateKey = v
	}
	if v := os.Getenv("JWKS_KEY_ID"); v != "" {
		c.JwksKeyID = v
	}
	if raw, exists := os.LookupEnv("TENANT_SCOPED_TOKEN_CLAIMS_V1"); exists {
		switch strings.TrimSpace(raw) {
		case "true":
			c.TenantScopedTokenClaimsV1 = true
		case "false":
			c.TenantScopedTokenClaimsV1 = false
		default:
			return nil, fmt.Errorf("TENANT_SCOPED_TOKEN_CLAIMS_V1 must be true or false")
		}
	}
	if raw, exists := os.LookupEnv("TENANT_SCOPED_TOKEN_CLAIMS_V1_TENANTS"); exists {
		c.TenantScopedTokenClaimsV1Tenants = nil
		if strings.TrimSpace(raw) != "" {
			c.TenantScopedTokenClaimsV1Tenants = strings.Split(raw, ",")
		}
	}
	c.TenantScopedTokenClaimsV1Tenants, err = canonicalTenantAllowlist(c.TenantScopedTokenClaimsV1Tenants)
	if err != nil {
		return nil, err
	}
	if c.TenantScopedTokenClaimsV1 && len(c.TenantScopedTokenClaimsV1Tenants) == 0 {
		return nil, fmt.Errorf("tenantScopedTokenClaimsV1 requires a non-empty tenant allowlist")
	}
	if raw, exists := os.LookupEnv("EXACT_MEMBERSHIP_READ_ROUTES_V1"); exists {
		switch strings.TrimSpace(raw) {
		case "true":
			c.ExactMembershipReadRoutesV1 = true
		case "false":
			c.ExactMembershipReadRoutesV1 = false
		default:
			return nil, fmt.Errorf("EXACT_MEMBERSHIP_READ_ROUTES_V1 must be true or false")
		}
	}
	if raw, exists := os.LookupEnv("EXACT_MEMBERSHIP_READ_ROUTES_V1_TENANTS"); exists {
		c.ExactMembershipReadRoutesV1Tenants = nil
		if strings.TrimSpace(raw) != "" {
			c.ExactMembershipReadRoutesV1Tenants = strings.Split(raw, ",")
		}
	}
	c.ExactMembershipReadRoutesV1Tenants, err = canonicalNamedTenantAllowlist("exactMembershipReadRoutesV1Tenants", c.ExactMembershipReadRoutesV1Tenants)
	if err != nil {
		return nil, err
	}
	if c.ExactMembershipReadRoutesV1 && len(c.ExactMembershipReadRoutesV1Tenants) == 0 {
		return nil, fmt.Errorf("exactMembershipReadRoutesV1 requires a non-empty tenant allowlist")
	}
	if c.ExactMembershipReadRoutesV1 {
		if err = loadSecretFile("EXACT_MEMBERSHIP_PAGE_TOKEN_SECRET_FILE", &c.ExactMembershipPageTokenSecret); err != nil {
			return nil, err
		}
	}
	if raw, exists := os.LookupEnv("MEMBERSHIP_V2_WRITE_ROUTES_V1"); exists {
		switch strings.TrimSpace(raw) {
		case "true":
			c.MembershipV2WriteRoutesV1 = true
		case "false":
			c.MembershipV2WriteRoutesV1 = false
		default:
			return nil, fmt.Errorf("MEMBERSHIP_V2_WRITE_ROUTES_V1 must be true or false")
		}
	}
	if raw, exists := os.LookupEnv("MEMBERSHIP_V2_WRITE_ROUTES_V1_TENANTS"); exists {
		c.MembershipV2WriteRoutesV1Tenants = nil
		if strings.TrimSpace(raw) != "" {
			c.MembershipV2WriteRoutesV1Tenants = strings.Split(raw, ",")
		}
	}
	c.MembershipV2WriteRoutesV1Tenants, err = canonicalNamedTenantAllowlist("membershipV2WriteRoutesV1Tenants", c.MembershipV2WriteRoutesV1Tenants)
	if err != nil {
		return nil, err
	}
	if c.MembershipV2WriteRoutesV1 && (!c.TenantScopedTokenClaimsV1 || !c.ExactMembershipReadRoutesV1 || len(c.MembershipV2WriteRoutesV1Tenants) == 0 ||
		!slices.Equal(c.MembershipV2WriteRoutesV1Tenants, c.ExactMembershipReadRoutesV1Tenants) ||
		!slices.Equal(c.MembershipV2WriteRoutesV1Tenants, c.TenantScopedTokenClaimsV1Tenants)) {
		return nil, fmt.Errorf("membershipV2WriteRoutesV1 requires matching exact-read and tenant-scope canary allowlists")
	}
	if c.IssuerBaseURL == "" {
		log.Println("WARNING: IssuerBaseURL not set. Using http://localhost:8080")
		c.IssuerBaseURL = "http://localhost:8080"
	}
	if c.DefaultAudience == "" {
		c.DefaultAudience = "tikti"
	}
	if c.JwksKeyID == "" {
		c.JwksKeyID = "tikti-local-1"
	}
	if c.HTTP.ReadHeaderTimeoutSeconds == 0 {
		c.HTTP.ReadHeaderTimeoutSeconds = 2
	}
	if c.HTTP.ReadTimeoutSeconds == 0 {
		c.HTTP.ReadTimeoutSeconds = 5
	}
	if c.HTTP.WriteTimeoutSeconds == 0 {
		c.HTTP.WriteTimeoutSeconds = 10
	}
	if c.HTTP.IdleTimeoutSeconds == 0 {
		c.HTTP.IdleTimeoutSeconds = 60
	}
	if c.HTTP.MaxHeaderBytes == 0 {
		c.HTTP.MaxHeaderBytes = 1 << 20
	}
	if c.HTTP.ReadHeaderTimeoutSeconds < 1 || c.HTTP.ReadHeaderTimeoutSeconds > 2 ||
		c.HTTP.ReadTimeoutSeconds < 1 || c.HTTP.ReadTimeoutSeconds > 60 ||
		c.HTTP.WriteTimeoutSeconds < 1 || c.HTTP.WriteTimeoutSeconds > 120 ||
		c.HTTP.IdleTimeoutSeconds < 1 || c.HTTP.IdleTimeoutSeconds > 300 ||
		c.HTTP.MaxHeaderBytes < 4096 || c.HTTP.MaxHeaderBytes > 1<<20 {
		return nil, fmt.Errorf("http server limits are outside the supported production bounds")
	}
	origins, err := normalizeOrigins(c.HTTP.AllowedOrigins)
	if err != nil {
		return nil, err
	}
	c.HTTP.AllowedOrigins = origins
	c.ForwardAuth.AccessCookieName = strings.TrimSpace(c.ForwardAuth.AccessCookieName)
	if strings.ContainsAny(c.ForwardAuth.AccessCookieName, " \t\r\n;,=") {
		return nil, fmt.Errorf("forwardAuth.accessCookieName contains invalid characters")
	}
	if value := strings.TrimSpace(os.Getenv("WORKLOAD_IDENTITY_ISSUER")); value != "" {
		c.WorkloadIdentity.Issuer = value
	}
	if value := strings.TrimSpace(os.Getenv("WORKLOAD_IDENTITY_AUDIENCE")); value != "" {
		c.WorkloadIdentity.Audience = value
	}
	if value := strings.TrimSpace(os.Getenv("WORKLOAD_IDENTITY_JWKS_URL")); value != "" {
		c.WorkloadIdentity.JWKSURL = value
	}
	if value := strings.TrimSpace(os.Getenv("WORKLOAD_IDENTITY_JWKS_BEARER_TOKEN_FILE")); value != "" {
		c.WorkloadIdentity.JWKSBearerTokenFile = value
	}
	c.WorkloadIdentity.Issuer = optionalExpandedValue(c.WorkloadIdentity.Issuer)
	c.WorkloadIdentity.JWKSURL = optionalExpandedValue(c.WorkloadIdentity.JWKSURL)
	c.WorkloadIdentity.JWKSBearerTokenFile = optionalExpandedValue(c.WorkloadIdentity.JWKSBearerTokenFile)
	if len(c.WorkloadIdentity.Providers) > 16 {
		return nil, fmt.Errorf("workload identity supports at most 16 providers")
	}
	seenProviderRefs := make(map[string]struct{}, len(c.WorkloadIdentity.Providers))
	seenProviderIssuers := make(map[string]struct{}, len(c.WorkloadIdentity.Providers)+1)
	if strings.TrimSpace(c.WorkloadIdentity.Issuer) != "" {
		seenProviderIssuers[c.WorkloadIdentity.Issuer] = struct{}{}
	}
	for index := range c.WorkloadIdentity.Providers {
		provider := &c.WorkloadIdentity.Providers[index]
		provider.ClusterRef = strings.TrimSpace(provider.ClusterRef)
		provider.Issuer = optionalExpandedValue(provider.Issuer)
		provider.JWKSURL = optionalExpandedValue(provider.JWKSURL)
		provider.JWKSBearerTokenFile = optionalExpandedValue(provider.JWKSBearerTokenFile)
		provider.Authentication = strings.ToLower(strings.TrimSpace(provider.Authentication))
		if provider.Authentication == "" {
			provider.Authentication = "none"
		}
		if provider.ClusterRef == "" || provider.Issuer == "" || provider.JWKSURL == "" {
			return nil, fmt.Errorf("workload identity provider %d requires clusterRef, issuer, and jwksUrl", index)
		}
		if strings.ContainsAny(provider.ClusterRef, " \t\r\n/:") || len(provider.ClusterRef) > 128 {
			return nil, fmt.Errorf("workload identity provider %d has an invalid clusterRef", index)
		}
		if provider.Authentication != "none" && provider.Authentication != "gcp" {
			return nil, fmt.Errorf("workload identity provider %d has an invalid authentication mode", index)
		}
		if provider.Authentication == "gcp" {
			if !validAuthenticatedGKEJWKSURL(provider.JWKSURL) || provider.JWKSBearerTokenFile != "" {
				return nil, fmt.Errorf("workload identity provider %d must use the authenticated GKE JWKS endpoint", index)
			}
		}
		if _, exists := seenProviderRefs[provider.ClusterRef]; exists {
			return nil, fmt.Errorf("workload identity provider clusterRef %q is duplicated", provider.ClusterRef)
		}
		if _, exists := seenProviderIssuers[provider.Issuer]; exists {
			return nil, fmt.Errorf("workload identity provider issuer %q is duplicated", provider.Issuer)
		}
		seenProviderRefs[provider.ClusterRef] = struct{}{}
		seenProviderIssuers[provider.Issuer] = struct{}{}
	}
	if c.WorkloadIdentity.Audience == "" {
		c.WorkloadIdentity.Audience = "tikti-workload-exchange"
	}
	if c.WorkloadIdentity.HTTPTimeoutSeconds == 0 {
		c.WorkloadIdentity.HTTPTimeoutSeconds = 5
	}
	if c.WorkloadIdentity.JWKSCacheTTLSeconds == 0 {
		c.WorkloadIdentity.JWKSCacheTTLSeconds = 300
	}
	if c.WorkloadIdentity.AccessTokenTTLSeconds == 0 {
		c.WorkloadIdentity.AccessTokenTTLSeconds = 300
	}
	if c.WorkloadIdentity.HTTPTimeoutSeconds, err = positiveEnvInt("WORKLOAD_IDENTITY_HTTP_TIMEOUT_SECONDS", c.WorkloadIdentity.HTTPTimeoutSeconds, 60); err != nil {
		return nil, err
	}
	if c.WorkloadIdentity.JWKSCacheTTLSeconds, err = positiveEnvInt("WORKLOAD_IDENTITY_JWKS_CACHE_TTL_SECONDS", c.WorkloadIdentity.JWKSCacheTTLSeconds, 86400); err != nil {
		return nil, err
	}
	if c.WorkloadIdentity.AccessTokenTTLSeconds, err = positiveEnvInt("WORKLOAD_IDENTITY_ACCESS_TOKEN_TTL_SECONDS", c.WorkloadIdentity.AccessTokenTTLSeconds, 3600); err != nil {
		return nil, err
	}
	if (strings.TrimSpace(c.WorkloadIdentity.Issuer) == "") != (strings.TrimSpace(c.WorkloadIdentity.JWKSURL) == "") {
		return nil, fmt.Errorf("workload identity issuer and jwksUrl must be configured together")
	}
	// SAML defaults
	if c.SAML.ACS.DeliveryMode == "" {
		c.SAML.ACS.DeliveryMode = "cookie"
	}
	if c.SAML.ACS.CookieSameSite == "" {
		c.SAML.ACS.CookieSameSite = "Lax"
	}
	if c.SAML.ACS.CookieName == "" {
		c.SAML.ACS.CookieName = "tikti_idt"
	}
	if c.SAML.ACS.PostLoginURL == "" {
		c.SAML.ACS.PostLoginURL = "/dashboard"
	}
	if len(c.SAML.SP.AllowedSigAlgs) == 0 {
		c.SAML.SP.AllowedSigAlgs = []string{"rsa-sha256"}
	}
	return &c, nil
}

func validAuthenticatedGKEJWKSURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Port() != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	path := parsed.EscapedPath()
	if host == "container.googleapis.com" {
		return strings.HasPrefix(path, "/v1/projects/") && strings.HasSuffix(path, "/jwks")
	}
	dnsPrefix, found := strings.CutSuffix(host, ".gke.goog")
	return found && dnsPrefix != "" && path == "/openid/v1/jwks"
}

func loadSecretFile(environmentVariable string, target *string) error {
	path := strings.TrimSpace(os.Getenv(environmentVariable))
	if path == "" {
		return nil
	}
	// #nosec G304 G703 -- the path is supplied only by the trusted deployment
	// manifest and is validated as one bounded regular Secret Manager CSI file.
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s: %w", environmentVariable, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 1<<20 {
		return fmt.Errorf("%s must not point to an empty file and must be a regular file no larger than 1 MiB", environmentVariable)
	}
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return fmt.Errorf("%s could not be read within the 1 MiB limit", environmentVariable)
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return fmt.Errorf("%s points to an empty file", environmentVariable)
	}
	*target = value
	return nil
}

func positiveEnvInt(name string, fallback, maximum int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		if fallback < 1 || fallback > maximum {
			return 0, fmt.Errorf("%s must be between 1 and %d", name, maximum)
		}
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > maximum {
		return 0, fmt.Errorf("%s must be between 1 and %d", name, maximum)
	}
	return value, nil
}

func optionalExpandedValue(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		return ""
	}
	return value
}

func canonicalTenantAllowlist(values []string) ([]string, error) {
	return canonicalNamedTenantAllowlist("tenantScopedTokenClaimsV1Tenants", values)
}

func canonicalNamedTenantAllowlist(name string, values []string) ([]string, error) {
	if len(values) > 128 {
		return nil, fmt.Errorf("%s supports at most 128 tenants", name)
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if !canonicalTenantID(value) {
			return nil, fmt.Errorf("%s contains an invalid tenant", name)
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("%s contains a duplicate tenant", name)
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func canonicalTenantID(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range []byte(value) {
		if strings.IndexByte("abcdefghijklmnopqrstuvwxyz0123456789-", character) < 0 {
			return false
		}
	}
	return true
}

func normalizeOrigins(origins []string) ([]string, error) {
	normalized := make([]string, 0, len(origins))
	seen := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin == "*" {
			return nil, fmt.Errorf("http.allowedOrigins must not contain a wildcard")
		}
		parsed, err := url.Parse(origin)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
			parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") ||
			parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("http.allowedOrigins must contain HTTP(S) origins")
		}
		value := strings.ToLower(parsed.Scheme + "://" + parsed.Host)
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized, nil
}
