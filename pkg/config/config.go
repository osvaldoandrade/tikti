package config

import (
	"fmt"
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config captures runtime parameters loaded from YAML or the environment.
type Config struct {
	Port            int        `yaml:"port"`
	RedisAddr       string     `yaml:"redisAddr"`
	RedisHost       string     `yaml:"redisHost"`
	RedisPort       int        `yaml:"redisPort"`
	RedisDB         int        `yaml:"redisDb"`
	RedisPassword   string     `yaml:"redisPassword"`
	RedisURL        string     `yaml:"redisUrl"`
	JwtSecret       string     `yaml:"jwtSecret"`
	ApiKey          string     `yaml:"apiKey"`
	IssuerBaseURL   string     `yaml:"issuerBaseUrl"`
	DefaultAudience string     `yaml:"defaultAudience"`
	JwksPrivateKey  string     `yaml:"jwksPrivateKey"`
	JwksKeyID       string     `yaml:"jwksKeyId"`
	SAML            SAMLConfig `yaml:"saml"`
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
	RequireAssertionSigned    bool          `yaml:"requireAssertionSigned"`
	RequireEncryptedAssertion bool          `yaml:"requireEncryptedAssertion"`
}

// UnmarshalYAML converts clockSkewSeconds and requestTTLSeconds from integer
// seconds into time.Duration values.
func (s *SPConfig) UnmarshalYAML(value *yaml.Node) error {
	type raw SPConfig // prevent recursion
	var aux struct {
		raw              `yaml:",inline"`
		ClockSkewSec     int `yaml:"clockSkewSeconds"`
		RequestTTLSec    int `yaml:"requestTTLSeconds"`
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
	SessionTTL     int    `yaml:"sessionTTL"`
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
	// SAML defaults
	if c.SAML.ACS.DeliveryMode == "" {
		c.SAML.ACS.DeliveryMode = "cookie"
	}
	if c.SAML.ACS.CookieSameSite == "" {
		c.SAML.ACS.CookieSameSite = "Lax"
	}
	if len(c.SAML.SP.AllowedSigAlgs) == 0 {
		c.SAML.SP.AllowedSigAlgs = []string{"rsa-sha256"}
	}
	return &c, nil
}
