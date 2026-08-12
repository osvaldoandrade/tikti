package controllers

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestRoleControllerPutStrictContract(t *testing.T) {
	cfg, key := roleAccessConfig(t)
	auth := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"sub": "operator", "scope": platformTenantAdminScope, "tid": "other",
	})
	bearer := func(claims jwt.MapClaims) string { return "Bearer " + signRoleAccessToken(t, key, claims) }
	var nextErr error
	created := true
	svc := &fakeRoleService{createWithNameFn: func(_ context.Context, tenantID, name string, req domain.RolePutReq) (*domain.RoleResp, bool, error) {
		if tenantID != "bereia" || name != "bereia-read" || len(req.Permissions) != 1 || req.Permissions[0] != "scope:read" {
			t.Fatalf("service input = %q %q %+v", tenantID, name, req)
		}
		return &domain.RoleResp{Name: name, Permissions: req.Permissions}, created, nextErr
	}}
	router := gin.New()
	router.PUT("/tenants/:tenantId/roles/:roleName", NewRoleController(svc, cfg).Put)
	valid := `{"permissions":["scope:read"]}`
	exact := valid + strings.Repeat(" ", rolePutBodyLimit-len(valid))
	delimiterOver := valid[:len(valid)-1] + strings.Repeat(" ", rolePutBodyLimit-len(valid)+1) + `}`
	tests := []struct {
		name, body, media, authorization string
		err                              error
		created                          bool
		want                             int
	}{
		{name: "created", body: valid, media: "application/json; charset=utf-8", created: true, want: http.StatusCreated},
		{name: "replay", body: valid, media: "application/json", created: false, want: http.StatusOK},
		{name: "invalid service", body: valid, media: "application/json", err: domain.ErrInvalidArgument, want: http.StatusBadRequest},
		{name: "conflict", body: valid, media: "application/json", err: domain.ErrRoleConflict, want: http.StatusConflict},
		{name: "storage", body: valid, media: "application/json", err: errors.New("redis secret"), want: http.StatusInternalServerError},
		{name: "unknown", body: `{"permissions":["scope:read"],"extra":1}`, media: "application/json", want: http.StatusBadRequest},
		{name: "duplicate key", body: `{"permissions":["scope:read"],"permissions":["scope:read"]}`, media: "application/json", want: http.StatusBadRequest},
		{name: "case variant", body: `{"Permissions":["scope:read"]}`, media: "application/json", want: http.StatusBadRequest},
		{name: "null", body: `{"permissions":null}`, media: "application/json", want: http.StatusBadRequest},
		{name: "non-string permission", body: `{"permissions":[1]}`, media: "application/json", want: http.StatusBadRequest},
		{name: "missing", body: `{}`, media: "application/json", want: http.StatusBadRequest},
		{name: "truncated", body: `{"permissions":["scope:read"]`, media: "application/json", want: http.StatusBadRequest},
		{name: "trailing", body: valid + `{}`, media: "application/json", want: http.StatusBadRequest},
		{name: "top level", body: `[]`, media: "application/json", want: http.StatusBadRequest},
		{name: "exact limit", body: exact, media: "application/json", created: true, want: http.StatusCreated},
		{name: "over limit", body: exact + " ", media: "application/json", want: http.StatusRequestEntityTooLarge},
		{name: "delimiter over limit", body: delimiterOver, media: "application/json", want: http.StatusRequestEntityTooLarge},
		{name: "wrong media", body: valid, media: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "missing media", body: valid, want: http.StatusUnsupportedMediaType},
		{name: "missing bearer", body: valid, media: "application/json", authorization: " ", want: http.StatusUnauthorized},
		{name: "raw bearer rejected", body: valid, media: "application/json", authorization: strings.TrimPrefix(auth, "Bearer "), want: http.StatusUnauthorized},
		{name: "local wrong tenant", body: valid, media: "application/json", authorization: bearer(jwt.MapClaims{"sub": "operator", "scope": tenantIdentityWriteScope, "tid": "other"}), want: http.StatusForbidden},
		{name: "local matching tenant", body: valid, media: "application/json", authorization: bearer(jwt.MapClaims{"sub": "operator", "scope": tenantIdentityWriteScope, "tid": "bereia"}), created: true, want: http.StatusCreated},
		{name: "missing subject", body: valid, media: "application/json", authorization: bearer(jwt.MapClaims{"scope": platformTenantAdminScope}), want: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nextErr, created = test.err, test.created
			req := httptest.NewRequest(http.MethodPut, "/tenants/bereia/roles/bereia-read", strings.NewReader(test.body))
			requestAuth := test.authorization
			if requestAuth == "" {
				requestAuth = auth
			}
			req.Header.Set("Authorization", requestAuth)
			req.Header.Set("Content-Type", test.media)
			req.Header.Set("X-Request-Id", "req-role-contract")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != test.want || test.name == "storage" && strings.Contains(rec.Body.String(), "redis secret") {
				t.Fatalf("response = %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRoleControllerReadAuthorizationAndErrors(t *testing.T) {
	cfg, key := roleAccessConfig(t)
	bearer := func(claims jwt.MapClaims) string { return "Bearer " + signRoleAccessToken(t, key, claims) }
	platform := bearer(jwt.MapClaims{"sub": "platform-operator", "scope": platformTenantAdminScope, "tid": "home"})
	localRead := bearer(jwt.MapClaims{"sub": "tenant-operator", "scope": tenantIdentityReadScope, "tid": "bereia"})
	localWrite := bearer(jwt.MapClaims{"sub": "tenant-operator", "scope": tenantIdentityWriteScope, "tid": "bereia"})
	storageCanary := errors.New("redis-password=must-not-leak")
	svc := &fakeRoleService{
		getByNameFn: func(_ context.Context, tenantID, roleName string) (*domain.RoleResp, error) {
			switch roleName {
			case "missing":
				return nil, domain.ErrRoleNotFound
			case "storage":
				return nil, storageCanary
			case "bad-role":
				return nil, domain.ErrInvalidArgument
			}
			if tenantID == "bad-tenant" {
				return nil, domain.ErrInvalidTenant
			}
			return &domain.RoleResp{Name: roleName, Permissions: []string{"scope:permission-canary"}}, nil
		},
		listCanonicalFn: func(_ context.Context, tenantID string) ([]*domain.RoleResp, error) {
			if tenantID == "storage" {
				return nil, storageCanary
			}
			return []*domain.RoleResp{{Name: "bereia-read", Permissions: []string{"scope:permission-canary"}}}, nil
		},
	}
	router := gin.New()
	controller := NewRoleController(svc, cfg)
	router.GET("/tenants/:tenantId/roles", controller.ListAdmin)
	router.GET("/tenants/:tenantId/roles/:roleName", controller.Get)
	var audit bytes.Buffer
	previousLogOutput := log.Writer()
	log.SetOutput(&audit)
	t.Cleanup(func() { log.SetOutput(previousLogOutput) })
	tests := []struct {
		name, target, authorization string
		want                        int
		body                        string
	}{
		{name: "platform exact cross tenant", target: "/tenants/bereia/roles/bereia-read", authorization: platform, want: http.StatusOK, body: `"name":"bereia-read"`},
		{name: "platform list cross tenant", target: "/tenants/bereia/roles", authorization: platform, want: http.StatusOK, body: `"name":"bereia-read"`},
		{name: "local read exact", target: "/tenants/bereia/roles/bereia-read", authorization: localRead, want: http.StatusOK},
		{name: "local read list", target: "/tenants/bereia/roles", authorization: localRead, want: http.StatusOK},
		{name: "local write exact", target: "/tenants/bereia/roles/bereia-read", authorization: localWrite, want: http.StatusOK},
		{name: "local write implies read", target: "/tenants/bereia/roles", authorization: localWrite, want: http.StatusOK},
		{name: "local foreign target", target: "/tenants/storifly/roles/bereia-read", authorization: localRead, want: http.StatusForbidden},
		{name: "scope suffix", target: "/tenants/bereia/roles/bereia-read", authorization: bearer(jwt.MapClaims{"sub": "operator", "scope": tenantIdentityReadScope + "-extra", "tid": "bereia"}), want: http.StatusForbidden},
		{name: "missing subject", target: "/tenants/bereia/roles", authorization: bearer(jwt.MapClaims{"scope": platformTenantAdminScope}), want: http.StatusForbidden},
		{name: "missing bearer", target: "/tenants/bereia/roles", authorization: " ", want: http.StatusUnauthorized},
		{name: "raw token", target: "/tenants/bereia/roles", authorization: strings.TrimPrefix(platform, "Bearer "), want: http.StatusUnauthorized},
		{name: "missing exact", target: "/tenants/bereia/roles/missing", authorization: platform, want: http.StatusNotFound, body: `{"error":"role not found"}`},
		{name: "invalid tenant", target: "/tenants/bad-tenant/roles/bereia-read", authorization: platform, want: http.StatusBadRequest, body: `{"error":"invalid tenant"}`},
		{name: "invalid role", target: "/tenants/bereia/roles/bad-role", authorization: platform, want: http.StatusBadRequest, body: `{"error":"invalid argument"}`},
		{name: "get storage redacted", target: "/tenants/bereia/roles/storage", authorization: platform, want: http.StatusInternalServerError, body: `{"error":"could not read role"}`},
		{name: "list storage redacted", target: "/tenants/storage/roles", authorization: platform, want: http.StatusInternalServerError, body: `{"error":"could not list roles"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, test.target, nil)
			req.Header.Set("Authorization", test.authorization)
			req.Header.Set("X-Request-Id", "req-role-read")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != test.want || test.body != "" && !strings.Contains(rec.Body.String(), test.body) || strings.Contains(rec.Body.String(), storageCanary.Error()) {
				t.Fatalf("response = %d %s", rec.Code, rec.Body.String())
			}
		})
	}
	logged := audit.String()
	for _, expected := range []string{"event=tenant_role_get", "event=tenant_role_list", `actor="platform-operator"`, `tenant="bereia"`, `role="*"`, `request_id="req-role-read"`, "result=success", "result=not_found", "result=invalid", "result=failure"} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("audit log missing %q: %s", expected, logged)
		}
	}
	for _, forbidden := range []string{"scope:permission-canary", storageCanary.Error(), strings.TrimPrefix(platform, "Bearer ")} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("audit log disclosed %q: %s", forbidden, logged)
		}
	}
	bounded := strings.Repeat("x", 129)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.Header.Set("X-Request-Id", bounded)
	logRoleRead(ctx, "tenant_role_get", bounded, bounded, bounded, "success")
	if strings.Contains(audit.String(), bounded) {
		t.Fatal("audit metadata exceeded its 128-character bound")
	}
}

func FuzzDecodeRolePut(f *testing.F) {
	for _, seed := range []string{
		`{"permissions":["scope:read"]}`, `{"permissions":null}`,
		`{"Permissions":[]}`, `{"permissions":[],"permissions":[]}`, `{"permissions":[]} {}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > rolePutBodyLimit {
			return
		}
		_, _ = decodeRolePut(strings.NewReader(string(input)))
	})
}

func TestSAMLAdminControllerContractCoverage(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	controller := NewSAMLAdminController(saml.NewAdminService(saml.NewRedisStore(client), saml.MetadataHTTPFetcher{}, "https://issuer", nil))
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
	check(http.MethodPut, "/saml/bereia", `{`, http.StatusBadRequest)
	check(http.MethodPut, "/saml/bereia", `{}{`, http.StatusBadRequest)
	metadata, _ := os.ReadFile("../saml/testdata/idp_okta.xml")
	body := `{"metadataXml":` + strconv.Quote(string(metadata)) + `}`
	check(http.MethodPut, "/saml/bereia", body, http.StatusOK)
	check(http.MethodDelete, "/saml/bereia", "", http.StatusNoContent)
	check(http.MethodPut, "/unavailable/bereia", body, http.StatusServiceUnavailable)
	check(http.MethodDelete, "/unavailable/bereia", "", http.StatusServiceUnavailable)
}

func roleAccessConfig(t *testing.T) (*config.Config, any) {
	privateKey, _ := os.ReadFile("../../hack/saml/sp.key.sample")
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	return &config.Config{JwksPrivateKey: string(privateKey), IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin"}, key
}

func signRoleAccessToken(t *testing.T, key any, claims jwt.MapClaims) string {
	claims["iss"], claims["aud"], claims["exp"] = "https://tikti", "code-admin", time.Now().Add(time.Hour).Unix()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func FuzzDecodeMembershipV2Write(f *testing.F) {
	f.Add(`{"roles":["reader"]}`)
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = decodeMembershipV2Write(strings.NewReader(value))
	})
}
