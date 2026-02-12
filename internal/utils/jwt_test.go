package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func makeRSAPrivatePEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func TestParseRSAPrivateKey_EmptyPEM(t *testing.T) {
	if _, err := ParseRSAPrivateKey(""); err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseRSAPrivateKey_InvalidPEM(t *testing.T) {
	if _, err := ParseRSAPrivateKey("bad-pem"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseRSAPrivateKey_ValidPEM(t *testing.T) {
	pemStr := makeRSAPrivatePEM(t)
	key, err := ParseRSAPrivateKey(pemStr)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if key == nil {
		t.Fatalf("expected key")
	}
}
