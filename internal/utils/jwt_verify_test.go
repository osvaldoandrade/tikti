package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func makeRSAToken(t *testing.T, key *rsa.PrivateKey, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func TestValidateRS256_EmptyToken(t *testing.T) {
	if _, err := ValidateRS256("", &rsa.PublicKey{}, "", ""); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateRS256_NilPublicKey(t *testing.T) {
	if _, err := ValidateRS256("abc", nil, "", ""); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateRS256_InvalidAlg(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()})
	hsSigned, err := hs.SignedString([]byte("x"))
	if err != nil {
		t.Fatalf("sign hs: %v", err)
	}
	if _, err := ValidateRS256(hsSigned, &key.PublicKey, "", ""); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateRS256_InvalidIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed := makeRSAToken(t, key, jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "issuer-a",
		"aud": "aud-a",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := ValidateRS256(signed, &key.PublicKey, "issuer-b", "aud-a"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateRS256_InvalidAudienceString(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed := makeRSAToken(t, key, jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "issuer-a",
		"aud": "aud-a",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := ValidateRS256(signed, &key.PublicKey, "issuer-a", "aud-b"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateRS256_AudienceArray(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed := makeRSAToken(t, key, jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "issuer-a",
		"aud": []string{"aud-a", "aud-b"},
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	claims, err := ValidateRS256(signed, &key.PublicKey, "issuer-a", "aud-b")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if claims["sub"] != "u1" {
		t.Fatalf("unexpected sub: %v", claims["sub"])
	}
}

func TestValidateRS256_AudienceArrayMissing(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed := makeRSAToken(t, key, jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "issuer-a",
		"aud": []string{"aud-a"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := ValidateRS256(signed, &key.PublicKey, "issuer-a", "aud-b"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateRS256_MissingAudienceClaim_WhenExpected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed := makeRSAToken(t, key, jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "issuer-a",
		"sub": "u2",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := ValidateRS256(signed, &key.PublicKey, "issuer-a", "aud-a"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateRS256_InvalidAudienceType(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed := makeRSAToken(t, key, jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "issuer-a",
		"aud": 12345,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := ValidateRS256(signed, &key.PublicKey, "issuer-a", "aud-a"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateRS256_MissingExpClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed := makeRSAToken(t, key, jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "issuer-a",
		"aud": "aud-a",
		"sub": "u2",
	})
	if _, err := ValidateRS256(signed, &key.PublicKey, "issuer-a", "aud-a"); err == nil {
		t.Fatalf("expected error")
	}
}
