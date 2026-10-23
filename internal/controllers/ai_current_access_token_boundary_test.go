package controllers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAICurrentValidationRejectsEveryAmbiguousRequestDimension(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"query", func(r *http.Request) { r.URL.RawQuery = "subject=other" }, 400},
		{"empty query delimiter", func(r *http.Request) { r.URL.ForceQuery = true }, 400},
		{"unknown content length", func(r *http.Request) { r.ContentLength = -1 }, 400},
		{"transfer encoding", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, 400},
		{"trailer", func(r *http.Request) { r.Trailer = http.Header{"X-Identity": {"other"}} }, 400},
		{"undeclared body", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("identity")) }, 400},
		{"empty origin header", func(r *http.Request) { r.Header["Origin"] = []string{""} }, 400},
		{"cookie", func(r *http.Request) { r.Header.Set("Cookie", "synthetic=1") }, 400},
		{"no authorization", func(r *http.Request) { r.Header.Del("Authorization") }, 401},
		{"duplicate authorization", func(r *http.Request) { r.Header.Add("Authorization", "Bearer other") }, 401},
		{"lowercase scheme", func(r *http.Request) { r.Header.Set("Authorization", "bearer synthetic") }, 401},
		{"empty token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }, 401},
		{"extra segment", func(r *http.Request) { r.Header.Set("Authorization", "Bearer first second") }, 401},
		{"oversized token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 16385)) }, 401},
		{"tab in token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic\tvalue") }, 401},
		{"newline in token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic\nvalue") }, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &aiCurrentValidator{}
			e := gin.New()
			e.POST("/validate", NewAICurrentAccessTokenController(v).Validate)
			r := httptest.NewRequest(http.MethodPost, "/validate", nil)
			r.Header.Set("Authorization", "Bearer synthetic")
			tc.mutate(r)
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)
			if w.Code != tc.want || w.Body.Len() != 0 || v.calls != 0 {
				t.Fatalf("ambiguous request reached identity authority: status=%d calls=%d", w.Code, v.calls)
			}
			if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("identity response may be cached or sniffed")
			}
		})
	}
}

func TestAICurrentValidationWithoutAuthorityFailsClosed(t *testing.T) {
	for _, controller := range []*AICurrentAccessTokenController{nil, NewAICurrentAccessTokenController(nil)} {
		e := gin.New()
		e.POST("/validate", controller.Validate)
		r := httptest.NewRequest(http.MethodPost, "/validate", nil)
		r.Header.Set("Authorization", "Bearer synthetic")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable || w.Body.Len() != 0 {
			t.Fatalf("missing authority status = %d", w.Code)
		}
	}
}
