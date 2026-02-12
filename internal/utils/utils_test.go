package utils

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func signHS256(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func TestParseToken_EmptyToken(t *testing.T) {
	if _, err := ParseToken("  ", "secret"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseToken_DefaultSecret(t *testing.T) {
	signed := signHS256(t, "supersecret", jwt.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	claims, err := ParseToken(signed, "")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if claims["sub"] != "u1" {
		t.Fatalf("unexpected sub claim: %v", claims["sub"])
	}
}

func TestParseToken_InvalidSignature(t *testing.T) {
	signed := signHS256(t, "secret-a", jwt.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := ParseToken(signed, "secret-b"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseToken_MissingExpirationClaim(t *testing.T) {
	signed := signHS256(t, "secret", jwt.MapClaims{
		"sub": "u1",
	})
	if _, err := ParseToken(signed, "secret"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseToken_ExpiredToken(t *testing.T) {
	signed := signHS256(t, "secret", jwt.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	if _, err := ParseToken(signed, "secret"); err == nil {
		t.Fatalf("expected error")
	}
}
