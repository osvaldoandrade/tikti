package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type routeAIIdentityService struct{ calls int }

func (s *routeAIIdentityService) Ensure(context.Context, string) (*domain.AIGatewayIdentityResp, bool, error) {
	s.calls++
	return &domain.AIGatewayIdentityResp{}, false, nil
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
	routes := enabled.Routes()
	if len(routes) != 1 || routes[0].Method != http.MethodPut || routes[0].Path != "/v1/admin/tenants/:tenantId/ai-gateway/identity" {
		t.Fatalf("unexpected routes: %v", routes)
	}
	request := httptest.NewRequest(http.MethodPut, "/v1/admin/tenants/bereia/ai-gateway/identity", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	enabled.ServeHTTP(recorder, request)
	if recorder.Code == http.StatusOK || service.calls != 0 {
		t.Fatalf("missing service key reached the service: %d", recorder.Code)
	}
}
