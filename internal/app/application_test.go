package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

func TestValidateWorkloadIdentityRuntimeConfig(t *testing.T) {
	validKey := applicationTestPrivateKey(t, 2048)
	weakKey := applicationTestPrivateKey(t, 1024)
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{name: "nil", cfg: nil, wantErr: true},
		{name: "disabled", cfg: &config.Config{}},
		{name: "missing API key", cfg: workloadRuntimeConfig("", validKey), wantErr: true},
		{name: "unresolved API key", cfg: workloadRuntimeConfig("${API_KEY}", validKey), wantErr: true},
		{name: "invalid signing key", cfg: workloadRuntimeConfig("admin-key", "invalid"), wantErr: true},
		{name: "weak signing key", cfg: workloadRuntimeConfig("admin-key", weakKey), wantErr: true},
		{name: "valid", cfg: workloadRuntimeConfig("admin-key", validKey)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateWorkloadIdentityRuntimeConfig(test.cfg)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateWorkloadIdentityRuntimeConfig() error = %v", err)
			}
		})
	}
}

func workloadRuntimeConfig(apiKey, privateKey string) *config.Config {
	return &config.Config{
		ApiKey: apiKey, IssuerBaseURL: "https://tikti.example.com", JwksPrivateKey: privateKey, JwksKeyID: "kid-1",
		WorkloadIdentity: config.WorkloadIdentityConfig{Issuer: "https://kubernetes.example.com"},
	}
}

func applicationTestPrivateKey(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}
