package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
)

func TestBuildJWKS_NilKey(t *testing.T) {
	j, err := BuildJWKS(nil, "")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(j.Keys) != 0 {
		t.Fatalf("expected empty keys, got %d", len(j.Keys))
	}
}

func TestBuildJWKS_WithKey_DefaultKid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	j, err := BuildJWKS(key, "")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(j.Keys) != 1 {
		t.Fatalf("expected one key, got %d", len(j.Keys))
	}
	if j.Keys[0].Kid != "tikti-local-1" {
		t.Fatalf("unexpected kid: %s", j.Keys[0].Kid)
	}
	if j.Keys[0].N == "" || j.Keys[0].E == "" {
		t.Fatalf("expected modulus/exponent")
	}
}

func TestJWKS_Marshal(t *testing.T) {
	j := &JWKS{Keys: []JWK{{Kty: "RSA", Kid: "k1"}}}
	b, err := j.Marshal()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if _, ok := out["keys"]; !ok {
		t.Fatalf("expected keys field")
	}
}
