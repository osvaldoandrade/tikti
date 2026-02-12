package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestApiKey_EmptyExpected_AllowsRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ApiKey(""))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
}

func TestApiKey_MissingOrInvalid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ApiKey("k1"))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	cases := []string{
		"/x",
		"/x?key=wrong",
	}
	for _, path := range cases {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("path %q: expected 401, got %d", path, rec.Code)
		}
	}
}

func TestApiKey_ValidKey_AllowsRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ApiKey("k1"))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusAccepted) })

	req := httptest.NewRequest(http.MethodGet, "/x?key=k1", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
}
