package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeTemporaryPasswords struct{ setCalls int }

func (f *fakeTemporaryPasswords) SetTemporaryPassword(context.Context, domain.AdminTemporaryPasswordReq) error {
	f.setCalls++
	return nil
}
func (f *fakeTemporaryPasswords) ChangeTemporaryPassword(context.Context, domain.TemporaryPasswordChangeReq) error {
	return nil
}

func TestTemporaryPasswordPrivateRouteFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, key := range []string{"", "wrong-key", "actual-private-key"} {
		service := &fakeTemporaryPasswords{}
		controller := NewTemporaryPasswordController(service, "actual-private-key")
		engine := gin.New()
		engine.POST("/v1/internal/passwords/temporary", controller.AdminSet)
		request := httptest.NewRequest(http.MethodPost, "/v1/internal/passwords/temporary", strings.NewReader(`{"email":"user@conveste.example","userId":"user-1","temporaryPassword":"temporary-password-123"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Password-Reset-Service-Key", key)
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		if key == "actual-private-key" {
			if response.Code != http.StatusNoContent || service.setCalls != 1 {
				t.Fatalf("authorized request: status=%d calls=%d", response.Code, service.setCalls)
			}
		} else if response.Code != http.StatusUnauthorized || service.setCalls != 0 {
			t.Fatalf("unauthorized request: status=%d calls=%d", response.Code, service.setCalls)
		}
	}
}
