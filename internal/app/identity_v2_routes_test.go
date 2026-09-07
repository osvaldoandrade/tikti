package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

func TestIdentityV2RemovesSupersededTenantAdministrationRoutes(t *testing.T) {
	server := miniredis.RunT(t)
	application, err := NewApplication(&config.Config{RedisAddr: server.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Redis.Close() })
	router := application.Engine
	SetupMappings(router, &config.Config{}, nil, nil, nil, nil, nil, nil, saml.NewRedisStore(nil), nil)
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
		"GET /v1/admin/identity/directory/users",
		"POST /v1/admin/identity/directory/users",
		"GET /v1/admin/identity/directory/groups",
		"GET /v1/admin/identity/tenants/:tenantId/access-assignments",
		"PUT /v1/admin/identity/tenants/:tenantId/access-assignments/users/:userId",
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
		"POST /v1/accounts/signUp",
		"GET /v1/admin/tenants/:tenantId/memberships",
		"PUT /v1/admin/tenants/:tenantId/memberships/:userId",
	} {
		if routes[removed] {
			t.Fatalf("superseded route remains registered: %s", removed)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/accounts/changeTemporaryPassword", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code == http.StatusNotFound {
		t.Fatal("temporary-password change route is missing")
	}
}
