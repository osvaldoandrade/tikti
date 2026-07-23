package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config captures runtime parameters loaded from YAML or the environment.
type Config struct {
	Port             int                    `yaml:"port"`
	RedisAddr        string                 `yaml:"redisAddr"`
	RedisHost        string                 `yaml:"redisHost"`
	RedisPort        int                    `yaml:"redisPort"`
	RedisDB          int                    `yaml:"redisDb"`
	RedisPassword    string                 `yaml:"redisPassword"`
	RedisURL         string                 `yaml:"redisUrl"`
	JwtSecret        string                 `yaml:"jwtSecret"`
	ApiKey           string                 `yaml:"apiKey"`
	IssuerBaseURL    string                 `yaml:"issuerBaseUrl"`
	DefaultAudience  string                 `yaml:"defaultAudience"`
	JwksPrivateKey   string                 `yaml:"jwksPrivateKey"`
	JwksKeyID        string                 `yaml:"jwksKeyId"`
	WorkloadIdentity WorkloadIdentityConfig `yaml:"workloadIdentity"`
	SAML             SAMLConfig             `yaml:"saml"`
}

// WorkloadIdentityConfig validates Kubernetes projected ServiceAccount tokens
// and controls the short-lived access tokens issued to bound controllers.
type WorkloadIdentityConfig struct {
	Issuer                string `yaml:"issuer"`
	Audience              string `yaml:"audience"`
	JWKSURL               string `yaml:"jwksUrl"`
	JWKSBearerTokenFile   string `yaml:"jwksBearerTokenFile"`
	HTTPTimeoutSeconds    int    `yaml:"httpTimeoutSeconds"`
	JWKSCacheTTLSeconds   int    `yaml:"jwksCacheTtlSeconds"`
	AccessTokenTTLSeconds int    `yaml:"accessTokenTtlSeconds"`
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
