package controllers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

func TestRequireAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JwtSecret: "s1"}

	t.Run("missing auth", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		ok := requireAdmin(c, cfg)
		if ok {
			t.Fatalf("expected false")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer bad-token")
		c.Request = req
		ok := requireAdmin(c, cfg)
		if ok {
			t.Fatalf("expected false")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("non admin", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken(t, cfg.JwtSecret, "USER"))
		c.Request = req
		ok := requireAdmin(c, cfg)
		if ok {
			t.Fatalf("expected false")
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("admin", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken(t, cfg.JwtSecret, "ADMIN"))
		c.Request = req
		if !requireAdmin(c, cfg) {
			t.Fatalf("expected true")
		}
	})

	t.Run("admin access token", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": "http://tikti", "aud": "code-admin-api", "sub": "u1",
			"role": "ADMIN", "exp": time.Now().Add(time.Hour).Unix(),
		})
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		cfg := &config.Config{
			JwtSecret:       "s1",
			IssuerBaseURL:   "http://tikti",
			DefaultAudience: "code-admin-api",
			JwksPrivateKey: string(pem.EncodeToMemory(&pem.Block{
				Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
			})),
		}
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		c.Request = req
		if !requireAdmin(c, cfg) {
			t.Fatalf("expected RS256 admin access token to be accepted")
		}
	})
}

func TestRunCommandAsync(t *testing.T) {
	success := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return "ok", nil
	})
	if got := <-success; got != "ok" {
		t.Fatalf("unexpected result: %#v", got)
	}

	fail := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("boom")
	})
	got := <-fail
	if err, ok := got.(error); !ok || err.Error() != "boom" {
		t.Fatalf("expected boom error, got %#v", got)
	}
}
