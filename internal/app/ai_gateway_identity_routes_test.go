package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type routeAIIdentityService struct{ calls int }

func (s *routeAIIdentityService) Ensure(context.Context, string, string) (*domain.AIGatewayIdentityResp, bool, error) {
	s.calls++
	return &domain.AIGatewayIdentityResp{}, false, nil
}

func (s *routeAIIdentityService) Deactivate(context.Context, string) (*domain.AIGatewayDeactivationResp, bool, error) {
	s.calls++
	return &domain.AIGatewayDeactivationResp{}, false, nil
}

func TestAIGatewayIdentityRouteRequiresEnabledAIAndServiceKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	disabled := gin.New()
	service := &routeAIIdentityService{}
	setupAIGatewayIdentityMappings(disabled, &config.Config{ApiKey: "key"}, service, nil)
	if len(disabled.Routes()) != 0 {
		t.Fatalf("disabled AI registered routes: %v", disabled.Routes())
	}
	enabled := gin.New()
	cfg := &config.Config{ApiKey: "key"}
	cfg.AIGateway.Enabled = true
	setupAIGatewayIdentityMappings(enabled, cfg, service, nil)
	paths := []string{}
	for _, route := range enabled.Routes() {
		if route.Method != http.MethodPut {
			t.Fatalf("unexpected method: %v", route)
		}
		paths = append(paths, route.Path)
	}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"/v1/admin/tenants/:tenantId/ai-gateway/identity", "/v1/admin/tenants/:tenantId/ai-gateway/identity/deactivation"}) {
		t.Fatalf("unexpected routes: %v", paths)
	}
	for _, path := range []string{"/v1/admin/tenants/bereia/ai-gateway/identity", "/v1/admin/tenants/bereia/ai-gateway/identity/deactivation"} {
		request := httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		enabled.ServeHTTP(recorder, request)
		if recorder.Code == http.StatusOK || service.calls != 0 {
			t.Fatalf("missing service key reached the service at %s: %d", path, recorder.Code)
		}
	}
}
