package app

import (
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

func TestIdentityV2RemovesSupersededTenantAdministrationRoutes(t *testing.T) {
	router := gin.New()
	SetupMappings(router, &config.Config{}, nil, nil, nil, nil, nil, nil, nil, saml.NewRedisStore(nil), nil)
	routes := map[string]bool{}
	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = true
	}
	for _, current := range []string{
		"GET /v1/admin/identity/tenant-inventory",
		"GET /v1/admin/identity/tenants/:tenantId",
		"PUT /v1/admin/identity/tenants/:tenantId",
		"GET /v1/admin/tenants/:tenantId/roles",
		"PUT /v1/admin/tenants/:tenantId/roles/:roleName",
	} {
		if !routes[current] {
			t.Fatalf("missing Identity V2 route %s", current)
		}
	}
	for _, removed := range []string{
		"GET /v1/tenants",
		"POST /v1/tenants",
		"PUT /v1/tenants/:tenantId",
		"GET /v1/tenants/id/:id",
		"GET /v1/tenants/:tenantId/users",
		"POST /v1/tenants/:tenantId/users",
		"POST /v1/tenants/:tenantId/users/remove",
		"GET /v1/tenants/:tenantId/roles",
		"POST /v1/tenants/:tenantId/roles",
		"GET /v1/tenants/:tenantId/clients",
		"POST /v1/tenants/:tenantId/clients",
	} {
		if routes[removed] {
			t.Fatalf("superseded route remains registered: %s", removed)
		}
	}
}
