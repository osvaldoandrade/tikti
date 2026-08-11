package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

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
