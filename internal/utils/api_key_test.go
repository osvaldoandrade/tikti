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

func TestApiKey_HeaderTrimsSecretFileNewlineAndAvoidsQueryString(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ApiKey("k1\n"))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusAccepted) })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-API-Key", "k1")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
}

func TestRequiredApiKeyHeaderFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name     string
		expected string
		provided string
		want     int
	}{
		{name: "empty configuration", expected: "", provided: "anything", want: http.StatusUnauthorized},
		{name: "missing header", expected: "secret", want: http.StatusUnauthorized},
		{name: "wrong header", expected: "secret", provided: "other", want: http.StatusUnauthorized},
		{name: "valid header", expected: "secret", provided: "secret", want: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.Use(RequiredApiKeyHeader(test.expected))
			router.POST("/workloads/bindings", func(c *gin.Context) { c.Status(http.StatusNoContent) })
			req := httptest.NewRequest(http.MethodPost, "/workloads/bindings?key=secret", nil)
			if test.provided != "" {
				req.Header.Set("X-API-Key", test.provided)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d", recorder.Code, test.want)
			}
		})
	}
}
