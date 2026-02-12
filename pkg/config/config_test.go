package config

import (
	"os"
	"path/filepath"
	"testing"
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
