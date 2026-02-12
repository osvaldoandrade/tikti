package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

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
