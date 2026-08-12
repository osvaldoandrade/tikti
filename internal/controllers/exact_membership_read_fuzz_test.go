package controllers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCanonicalMembershipUserPathDotSegments(t *testing.T) {
	for value, want := range map[string]bool{
		".": false, "..": false, "": false, "A": true, "a..b": true,
		strings.Repeat("a", 128): true, strings.Repeat("a", 129): false, "user/bad": false,
	} {
		if got := canonicalMembershipUserPath(value); got != want {
			t.Errorf("canonicalMembershipUserPath(%q) = %t, want %t", value, got, want)
		}
	}
}

func FuzzExactMembershipListInput(f *testing.F) {
	for _, seed := range []string{"", "pageSize=1", "pageSize=200", "pageSize=0", "pageSize=1&pageSize=2", "pageToken=secret"} {
		f.Add(seed, "", false)
	}
	f.Fuzz(func(t *testing.T, rawQuery, token string, duplicate bool) {
		if len(rawQuery) > 1024 || len(token) > 1024 {
			return
		}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.URL.RawQuery = rawQuery
		request.Header.Add("X-Page-Token", token)
		if duplicate {
			request.Header.Add("X-Page-Token", token)
		}
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = request
		_, _, _ = exactMembershipListInput(ctx)
	})
}
