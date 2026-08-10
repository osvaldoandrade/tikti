package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestTenantController_CreateWithIDContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	created := true
	var createError error
	svc := &fakeTenantService{createWithIDFn: func(
		ctx context.Context,
		tenantID string,
		req domain.TenantCreateReq,
	) (*domain.TenantResp, bool, error) {
		return &domain.TenantResp{Id: tenantID, Name: req.Name, Slug: req.Slug}, created, createError
	}}
	controller := NewTenantController(svc, cfg)
	router := gin.New()
	router.PUT("/tenants/:tenantId", controller.CreateWithID)
	auth := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope,
		"role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	rec := performJSON(t, router, http.MethodPut, "/tenants/bereia", domain.TenantCreateReq{
		Name: "Bereia", Slug: "bereia",
	}, auth)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for creation, got %d", rec.Code)
	}
	if rec = performJSON(t, router, http.MethodPut, "/tenants/bereia", domain.TenantCreateReq{}, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without admin token, got %d", rec.Code)
	}
	created = false
	rec = performJSON(t, router, http.MethodPut, "/tenants/bereia", domain.TenantCreateReq{
		Name: "Bereia", Slug: "bereia",
	}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for replay, got %d", rec.Code)
	}
	createError = domain.ErrTenantConflict
	rec = performJSON(t, router, http.MethodPut, "/tenants/bereia", domain.TenantCreateReq{
		Name: "Other", Slug: "bereia",
	}, auth)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for mismatch, got %d", rec.Code)
	}
	createError = errors.New("storage failure")
	rec = performJSON(t, router, http.MethodPut, "/tenants/bereia", domain.TenantCreateReq{
		Name: "Bereia", Slug: "bereia",
	}, auth)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "storage failure") {
		t.Fatalf("expected redacted 500, got %d %s", rec.Code, rec.Body.String())
	}
	createError = domain.ErrInvalidArgument
	rec = performJSON(t, router, http.MethodPut, "/tenants/Bad", domain.TenantCreateReq{
		Name: "Bereia", Slug: "bereia",
	}, auth)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid argument, got %d", rec.Code)
	}
}

func TestTenantController_CreateWithIDRejectsInvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	called := false
	svc := &fakeTenantService{createWithIDFn: func(
		context.Context,
		string,
		domain.TenantCreateReq,
	) (*domain.TenantResp, bool, error) {
		called = true
		return &domain.TenantResp{Id: "bereia"}, true, nil
	}}
	router := gin.New()
	router.PUT("/tenants/:tenantId", NewTenantController(svc, cfg).CreateWithID)
	auth := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope,
		"role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	validPayload := `{"name":"Bereia","slug":"bereia"}`
	for _, test := range []struct {
		payload, contentType string
		status               int
		called               bool
	}{
		{payload: validPayload + strings.Repeat(" ", tenantCreateBodyLimit-len(validPayload)), status: http.StatusCreated, called: true},
		{payload: `{"name":"Bereia","slug":"bereia","status":"ACTIVE"}`, contentType: "application/json; charset=utf-8", status: http.StatusBadRequest},
		{payload: `{"Name":"Bereia","slug":"bereia"}`, status: http.StatusBadRequest},
		{payload: `{"name":"Bereia","name":"Other","slug":"bereia"}`, status: http.StatusBadRequest},
		{payload: `{"name":null,"slug":"bereia"}`, status: http.StatusBadRequest},
		{payload: `{"name":"Bereia"}`, status: http.StatusBadRequest},
		{payload: `{"name":"Bereia","slug":"bereia"} {}`, status: http.StatusBadRequest},
		{payload: validPayload + strings.Repeat(" ", tenantCreateBodyLimit-len(validPayload)+1), status: http.StatusRequestEntityTooLarge},
		{payload: `{"name":"Bereia","slug":"bereia"}`, contentType: "text/plain", status: http.StatusUnsupportedMediaType},
		{payload: `{"name":"Bereia","slug":"bereia"}`, status: http.StatusUnsupportedMediaType},
	} {
		called = false
		req := httptest.NewRequest(http.MethodPut, "/tenants/bereia", strings.NewReader(test.payload))
		req.Header.Set("Authorization", auth)
		if test.contentType == "" && test.status != http.StatusUnsupportedMediaType {
			test.contentType = "application/json"
		}
		req.Header.Set("Content-Type", test.contentType)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != test.status || called != test.called {
			t.Fatalf("expected status %d and called=%v, got %d and %v", test.status, test.called, rec.Code, called)
		}
	}
}

func TestTenantController_CreateWithIDRequiresPlatformAdminProvenance(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	calls := 0
	svc := &fakeTenantService{createWithIDFn: func(
		context.Context,
		string,
		domain.TenantCreateReq,
	) (*domain.TenantResp, bool, error) {
		calls++
		return &domain.TenantResp{Id: "bereia", Name: "Bereia", Slug: "bereia"}, true, nil
	}}
	router := gin.New()
	router.PUT("/tenants/:tenantId", NewTenantController(svc, cfg).CreateWithID)
	token := func(claims jwt.MapClaims) string {
		return "Bearer " + signRoleAccessToken(t, key, claims)
	}
	valid := jwt.MapClaims{
		"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope,
		"role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	}
	tests := []struct {
		name string
		auth string
		want int
	}{
		{name: "missing bearer", want: http.StatusUnauthorized},
		{name: "legacy HS admin", auth: "Bearer " + adminToken(t, "legacy", "ADMIN"), want: http.StatusUnauthorized},
		{name: "missing subject", auth: token(jwt.MapClaims{
			"scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin),
			domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
		}), want: http.StatusForbidden},
		{name: "missing provenance", auth: token(jwt.MapClaims{
			"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin),
		}), want: http.StatusForbidden},
		{name: "forged company admin", auth: token(jwt.MapClaims{
			"sub": "company-operator", "scope": domain.PlatformTenantAdminScope,
			"role": string(domain.RoleCompanyAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
		}), want: http.StatusForbidden},
		{name: "platform admin", auth: token(valid), want: http.StatusCreated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := calls
			rec := performJSON(t, router, http.MethodPut, "/tenants/bereia", domain.TenantCreateReq{
				Name: "Bereia", Slug: "bereia",
			}, test.auth)
			wantCalls := 0
			if test.want == http.StatusCreated {
				wantCalls = 1
			}
			if rec.Code != test.want || calls-before != wantCalls {
				t.Fatalf("response=%d calls=%d body=%s", rec.Code, calls-before, rec.Body.String())
			}
		})
	}
}

func FuzzDecodeTenantCreate(f *testing.F) {
	for _, seed := range []string{"", `[]`, `{"name":"Bereia","slug":"bereia"}`, `{"name":"a","name":"b","slug":"a"}`, `{"Name":"a","slug":"a"}`, `{"name":"a","slug":"a"} {}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > tenantCreateBodyLimit*2 {
			return
		}
		_, _ = decodeTenantCreate(strings.NewReader(input))
	})
}

func TestSAMLAdminControllerContract(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	service := saml.NewAdminService(saml.NewRedisStore(client), saml.MetadataHTTPFetcher{}, "https://issuer.example", nil)
	controller := NewSAMLAdminController(service)
	unavailable := NewSAMLAdminController(saml.NewAdminService(nil, saml.MetadataHTTPFetcher{}, "", nil))
	router := gin.New()
	router.GET("/saml/:tenantId", controller.Get)
	router.PUT("/saml/:tenantId", controller.Put)
	router.DELETE("/saml/:tenantId", controller.Delete)
	router.PUT("/unavailable/:tenantId", unavailable.Put)
	router.DELETE("/unavailable/:tenantId", unavailable.Delete)
	check := func(method, path, body string, want int) {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		if rec.Code != want {
			t.Fatalf("%s %s = %d: %s", method, path, rec.Code, rec.Body.String())
		}
	}
	check(http.MethodGet, "/saml/Bad", "", http.StatusUnprocessableEntity)
	check(http.MethodGet, "/saml/bereia", "", http.StatusOK)
	check(http.MethodPut, "/saml/bereia", `{`, http.StatusBadRequest)
	check(http.MethodPut, "/saml/bereia", `{}{`, http.StatusBadRequest)
	metadata, err := os.ReadFile("../saml/testdata/idp_okta.xml")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"metadataXml":` + strconv.Quote(string(metadata)) + `}`
	check(http.MethodPut, "/saml/bereia", body, http.StatusOK)
	check(http.MethodDelete, "/saml/bereia", "", http.StatusNoContent)
	check(http.MethodPut, "/unavailable/bereia", body, http.StatusServiceUnavailable)
	check(http.MethodDelete, "/unavailable/bereia", "", http.StatusServiceUnavailable)
}
