package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type aiCurrentValidator struct {
	calls int
	err   error
}

func (v *aiCurrentValidator) ValidateAIAccessToken(context.Context, string) (aigateway.Claims, error) {
	v.calls++
	return aigateway.Claims{}, v.err
}

func TestAICurrentValidationMachineOnlyBodylessContract(t *testing.T) {
	for _, tc := range []struct {
		name, body, origin string
		err                error
		want               int
	}{
		{name: "current", want: 204}, {name: "revoked", err: domain.ErrInvalidToken, want: 401}, {name: "authority-unavailable", err: domain.ErrAuthenticationUnavailable, want: 503}, {name: "body-attribution", body: `{"subject":"other"}`, want: 400}, {name: "browser", origin: "https://console.example", want: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &aiCurrentValidator{err: tc.err}
			e := gin.New()
			e.POST("/validate", NewAICurrentAccessTokenController(v).Validate)
			req := httptest.NewRequest(http.MethodPost, "/validate", nil)
			if tc.body != "" {
				req = httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(tc.body))
			}
			req.Header.Set("Authorization", "Bearer synthetic-test-token")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			e.ServeHTTP(w, req)
			if w.Code != tc.want || w.Body.Len() != 0 {
				t.Fatal("private token authority returned wrong status or body")
			}
			if tc.want == 400 && v.calls != 0 {
				t.Fatal("untrusted request reached authority")
			}
		})
	}
}
