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
		target   string
		want     int
	}{
		{name: "empty configuration", expected: "", provided: "anything", target: "/workloads/bindings", want: http.StatusUnauthorized},
		{name: "missing header", expected: "secret", target: "/workloads/bindings", want: http.StatusUnauthorized},
		{name: "wrong header", expected: "secret", provided: "other", target: "/workloads/bindings", want: http.StatusUnauthorized},
		{name: "valid header", expected: "secret", provided: "secret", target: "/workloads/bindings", want: http.StatusNoContent},
		{name: "valid header cannot accompany query key", expected: "secret", provided: "secret", target: "/workloads/bindings?key=secret", want: http.StatusUnauthorized},
		{name: "malformed semicolon query cannot hide key", expected: "secret", provided: "secret", target: "/workloads/bindings?key=secret;ignored=1", want: http.StatusUnauthorized},
		{name: "bad escape query fails closed", expected: "secret", provided: "secret", target: "/workloads/bindings?key=%ZZ", want: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.Use(RequiredApiKeyHeader(test.expected))
			handlerCalls := 0
			router.POST("/workloads/bindings", func(c *gin.Context) {
				handlerCalls++
				c.Status(http.StatusNoContent)
			})
			req := httptest.NewRequest(http.MethodPost, test.target, nil)
			if test.provided != "" {
				req.Header.Set("X-API-Key", test.provided)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d", recorder.Code, test.want)
			}
			wantCalls := 0
			if test.want == http.StatusNoContent {
				wantCalls = 1
			}
			if handlerCalls != wantCalls {
				t.Fatalf("handler calls = %d, want %d", handlerCalls, wantCalls)
			}
		})
	}
}
