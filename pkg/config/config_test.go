package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tikti.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

func TestLoadConfig_FileMissing(t *testing.T) {
	if _, err := LoadConfig("/missing/file.yaml"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "port: [")
	if _, err := LoadConfig(path); err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	path := writeTempConfig(t, "{}")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if cfg.Port != 8080 {
		t.Fatalf("unexpected port: %d", cfg.Port)
	}
	if cfg.RedisAddr != "localhost:6379" {
		t.Fatalf("unexpected redis addr: %s", cfg.RedisAddr)
	}
	if cfg.RedisHost != "localhost" {
		t.Fatalf("unexpected redis host: %s", cfg.RedisHost)
	}
	if cfg.RedisPort != 6379 {
		t.Fatalf("unexpected redis port: %d", cfg.RedisPort)
	}
	if cfg.RedisDB != 0 {
		t.Fatalf("unexpected redis db: %d", cfg.RedisDB)
	}
	if cfg.JwtSecret != "supersecret" {
		t.Fatalf("unexpected secret")
	}
	if cfg.IssuerBaseURL != "http://localhost:8080" {
		t.Fatalf("unexpected issuer: %s", cfg.IssuerBaseURL)
	}
	if cfg.DefaultAudience != "tikti" {
		t.Fatalf("unexpected audience: %s", cfg.DefaultAudience)
	}
	if cfg.JwksKeyID != "tikti-local-1" {
		t.Fatalf("unexpected kid: %s", cfg.JwksKeyID)
	}
}

func TestLoadConfig_EnvExpansionAndOverrides(t *testing.T) {
	t.Setenv("REDIS_ADDR", "redis.internal:6379")
	t.Setenv("ISSUER_BASE_URL", "https://issuer.example")
	t.Setenv("DEFAULT_AUDIENCE", "aud-x")
	t.Setenv("JWKS_PRIVATE_KEY", "pem-x")
	t.Setenv("JWKS_KEY_ID", "kid-x")

	path := writeTempConfig(t, `
redisAddr: ${REDIS_ADDR}
issuerBaseUrl: http://from-file
defaultAudience: aud-file
jwksPrivateKey: pem-file
jwksKeyId: kid-file
`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if cfg.RedisAddr != "redis.internal:6379" {
		t.Fatalf("unexpected redisAddr: %s", cfg.RedisAddr)
	}
	if cfg.IssuerBaseURL != "https://issuer.example" {
		t.Fatalf("unexpected issuer: %s", cfg.IssuerBaseURL)
	}
	if cfg.DefaultAudience != "aud-x" {
		t.Fatalf("unexpected audience: %s", cfg.DefaultAudience)
	}
	if cfg.JwksPrivateKey != "pem-x" {
		t.Fatalf("unexpected private key")
	}
	if cfg.JwksKeyID != "kid-x" {
		t.Fatalf("unexpected kid: %s", cfg.JwksKeyID)
	}
}

func TestLoadConfig_WorkloadIdentityDefaultsAndOverrides(t *testing.T) {
	t.Setenv("WORKLOAD_IDENTITY_ISSUER", "https://kubernetes.example.com")
	t.Setenv("WORKLOAD_IDENTITY_JWKS_URL", "https://kubernetes.example.com/openid/v1/jwks")
	t.Setenv("WORKLOAD_IDENTITY_JWKS_BEARER_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	t.Setenv("WORKLOAD_IDENTITY_HTTP_TIMEOUT_SECONDS", "7")
	t.Setenv("WORKLOAD_IDENTITY_JWKS_CACHE_TTL_SECONDS", "600")
	t.Setenv("WORKLOAD_IDENTITY_ACCESS_TOKEN_TTL_SECONDS", "120")
	path := writeTempConfig(t, `{workloadIdentity: {audience: tikti-workload-exchange}}`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.WorkloadIdentity.Issuer != "https://kubernetes.example.com" || cfg.WorkloadIdentity.JWKSURL != "https://kubernetes.example.com/openid/v1/jwks" || cfg.WorkloadIdentity.Audience != "tikti-workload-exchange" {
		t.Fatalf("workload identity endpoints = %#v", cfg.WorkloadIdentity)
	}
	if cfg.WorkloadIdentity.JWKSBearerTokenFile != "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Fatalf("workload identity JWKS token file = %q", cfg.WorkloadIdentity.JWKSBearerTokenFile)
	}
	if cfg.WorkloadIdentity.HTTPTimeoutSeconds != 7 || cfg.WorkloadIdentity.JWKSCacheTTLSeconds != 600 || cfg.WorkloadIdentity.AccessTokenTTLSeconds != 120 {
		t.Fatalf("workload identity limits = %#v", cfg.WorkloadIdentity)
	}
}

func TestLoadConfig_WorkloadIdentityFailsClosed(t *testing.T) {
	t.Run("partial endpoint", func(t *testing.T) {
		t.Setenv("WORKLOAD_IDENTITY_ISSUER", "https://kubernetes.example.com")
		if _, err := LoadConfig(writeTempConfig(t, `{}`)); err == nil {
			t.Fatal("issuer without JWKS URL was accepted")
		}
	})
	t.Run("invalid lifetime", func(t *testing.T) {
		t.Setenv("WORKLOAD_IDENTITY_ACCESS_TOKEN_TTL_SECONDS", "3601")
		if _, err := LoadConfig(writeTempConfig(t, `{}`)); err == nil {
			t.Fatal("access token lifetime above one hour was accepted")
		}
	})
}

func TestLoadConfig_UnsetWorkloadIdentityPlaceholdersDisableExchange(t *testing.T) {
	path := writeTempConfig(t, `
workloadIdentity:
  issuer: ${WORKLOAD_IDENTITY_ISSUER}
  jwksUrl: ${WORKLOAD_IDENTITY_JWKS_URL}
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.WorkloadIdentity.Issuer != "" || cfg.WorkloadIdentity.JWKSURL != "" {
		t.Fatalf("unset workload placeholders = %#v", cfg.WorkloadIdentity)
	}
}

func TestSAMLConfig_DefaultDisabled(t *testing.T) {
	path := writeTempConfig(t, "{}")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SAML.Enabled {
		t.Fatalf("expected saml.enabled=false when absent, got true")
	}
}

func TestSAMLConfig_RequiresKeysWhenEnabled(t *testing.T) {
	path := writeTempConfig(t, `
saml:
  enabled: true
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if err := cfg.SAML.Validate(); err == nil {
		t.Fatalf("expected validation error for missing signingKeyPath")
	}
}

func TestSAMLConfig_DurationsParse(t *testing.T) {
	path := writeTempConfig(t, `
saml:
  sp:
    clockSkewSeconds: 5
    requestTTLSeconds: 300
  idp:
    refreshIntervalHours: 12
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SAML.SP.ClockSkew != 5*time.Second {
		t.Fatalf("unexpected clockSkew: %v", cfg.SAML.SP.ClockSkew)
	}
	if cfg.SAML.SP.RequestTTL != 300*time.Second {
		t.Fatalf("unexpected requestTTL: %v", cfg.SAML.SP.RequestTTL)
	}
	if cfg.SAML.IdP.RefreshInterval != 12*time.Hour {
		t.Fatalf("unexpected refreshInterval: %v", cfg.SAML.IdP.RefreshInterval)
	}
}

func TestSAMLConfig_AllowedSigAlgsDefault(t *testing.T) {
	path := writeTempConfig(t, "{}")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.SAML.SP.AllowedSigAlgs) != 1 || cfg.SAML.SP.AllowedSigAlgs[0] != "rsa-sha256" {
		t.Fatalf("unexpected allowedSigAlgs: %v", cfg.SAML.SP.AllowedSigAlgs)
	}
}

func TestSAMLConfig_SameSiteDefault(t *testing.T) {
	path := writeTempConfig(t, "{}")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SAML.ACS.CookieSameSite != "Lax" {
		t.Fatalf("unexpected cookieSameSite: %s", cfg.SAML.ACS.CookieSameSite)
	}
}

func TestSAMLConfig_ExampleYAMLParses(t *testing.T) {
	path := writeTempConfig(t, `
saml:
  enabled: true
  sp:
    entityID: "https://sp.example.com/metadata"
    acsURL: "https://sp.example.com/saml/acs"
    sloURL: "https://sp.example.com/saml/slo"
    signingKeyPath: "/etc/tikti/saml/sp-key.pem"
    signingCertPath: "/etc/tikti/saml/sp-cert.pem"
    encryptionKeyPath: "/etc/tikti/saml/enc-key.pem"
    encryptionCertPath: "/etc/tikti/saml/enc-cert.pem"
    keyBits: 2048
    clockSkewSeconds: 5
    requestTTLSeconds: 300
    allowedSigAlgs: ["rsa-sha256"]
    allowedDigestAlgs: ["sha256"]
    canonicalization: "http://www.w3.org/2001/10/xml-exc-c14n#"
    requireAssertionSigned: true
    requireEncryptedAssertion: false
  acs:
    deliveryMode: cookie
    cookieName: tikti_saml
    cookieDomain: ".example.com"
    cookieSameSite: Lax
    cookieSecure: true
    sessionTTL: 3600
  idp:
    metadataURL: "https://idp.example.com/metadata"
    refreshIntervalHours: 12
    trustedCertPaths:
      - /etc/tikti/saml/idp-ca.pem
    skipSignatureCheck: false
  discover:
    enabled: false
    protocolType: "SAML2Redirect"
    serviceURL: "https://sp.example.com/discovery"
  metrics:
    enabled: true
    namespace: "tikti_saml"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := cfg.SAML.Validate(); err != nil {
		t.Fatalf("validation failed: %v", err)
	}
}
