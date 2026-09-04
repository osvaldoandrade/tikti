package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type authorityCountingSAMLStore struct {
	saml.Store
	getCalls    int
	putCalls    int
	deleteCalls int
}

func (s *authorityCountingSAMLStore) GetIdP(context.Context, string) (saml.IdPRecord, error) {
	s.getCalls++
	return saml.IdPRecord{}, saml.ErrIdPNotFound
}

func (s *authorityCountingSAMLStore) PutIdP(context.Context, saml.IdPRecord) error {
	s.putCalls++
	return nil
}

func (s *authorityCountingSAMLStore) DeleteIdP(context.Context, string) error {
	s.deleteCalls++
	return nil
}

func (s *authorityCountingSAMLStore) calls() int {
	return s.getCalls + s.putCalls + s.deleteCalls
}

func TestSAMLAdminAuthorityRejectsForeignAndLegacyTokensBeforeStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.JwtSecret = "legacy-secret"
	store := &authorityCountingSAMLStore{}
	controller := NewSAMLAdminController(saml.NewAdminService(store, saml.MetadataHTTPFetcher{}, "https://issuer", nil))
	router := gin.New()
	router.GET("/admin/tenants/:tenantId/saml/idp", RequireSAMLAdminReadAuthority(cfg), controller.Get)
	router.PUT("/admin/tenants/:tenantId/saml/idp", RequireSAMLAdminWriteAuthority(cfg), controller.Put)
	router.DELETE("/admin/tenants/:tenantId/saml/idp", RequireSAMLAdminWriteAuthority(cfg), controller.Delete)

	bearer := func(claims jwt.MapClaims) string {
		return "Bearer " + signRoleAccessToken(t, key, claims)
	}
	localRead := bearer(jwt.MapClaims{"sub": "reader", "scope": tenantIdentityReadScope, "tid": "bereia"})
	localWrite := bearer(jwt.MapClaims{"sub": "writer", "scope": tenantIdentityWriteScope, "tid": "bereia"})
	foreignWrite := bearer(jwt.MapClaims{"sub": "writer", "scope": tenantIdentityWriteScope, "tid": "storifly"})
	platformWithoutProvenance := bearer(jwt.MapClaims{
		"sub": "platform", "scope": platformTenantAdminScope, "tid": "home", "role": string(domain.RoleAdmin),
	})
	hsToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "legacy", "scope": tenantIdentityWriteScope, "tid": "bereia", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(cfg.JwtSecret))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, method, target, authorization string
		want                                int
	}{
		{name: "missing bearer", method: http.MethodGet, target: "/admin/tenants/bereia/saml/idp", want: http.StatusUnauthorized},
		{name: "raw token", method: http.MethodGet, target: "/admin/tenants/bereia/saml/idp", authorization: strings.TrimPrefix(localRead, "Bearer "), want: http.StatusUnauthorized},
		{name: "legacy HS token", method: http.MethodDelete, target: "/admin/tenants/bereia/saml/idp", authorization: "Bearer " + hsToken, want: http.StatusUnauthorized},
		{name: "foreign read", method: http.MethodGet, target: "/admin/tenants/bereia/saml/idp", authorization: foreignWrite, want: http.StatusForbidden},
		{name: "foreign write", method: http.MethodPut, target: "/admin/tenants/bereia/saml/idp", authorization: foreignWrite, want: http.StatusForbidden},
		{name: "foreign delete", method: http.MethodDelete, target: "/admin/tenants/bereia/saml/idp", authorization: foreignWrite, want: http.StatusForbidden},
		{name: "read scope cannot write", method: http.MethodPut, target: "/admin/tenants/bereia/saml/idp", authorization: localRead, want: http.StatusForbidden},
		{name: "platform scope lacks provenance", method: http.MethodDelete, target: "/admin/tenants/bereia/saml/idp", authorization: platformWithoutProvenance, want: http.StatusForbidden},
		{name: "noncanonical tenant", method: http.MethodGet, target: "/admin/tenants/Bereia/saml/idp", authorization: localRead, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := store.calls()
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(`{"metadataXml":"ignored"}`))
			request.Header.Set("Authorization", test.authorization)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
			if store.calls() != before {
				t.Fatalf("denied request reached SAML store: before=%d after=%d", before, store.calls())
			}
		})
	}

	allowedRead := httptest.NewRequest(http.MethodGet, "/admin/tenants/bereia/saml/idp", nil)
	allowedRead.Header.Set("Authorization", localRead)
	allowedResponse := httptest.NewRecorder()
	router.ServeHTTP(allowedResponse, allowedRead)
	if allowedResponse.Code != http.StatusOK || store.getCalls != 1 {
		t.Fatalf("local read status=%d getCalls=%d body=%s", allowedResponse.Code, store.getCalls, allowedResponse.Body.String())
	}

	allowedDelete := httptest.NewRequest(http.MethodDelete, "/admin/tenants/bereia/saml/idp", nil)
	allowedDelete.Header.Set("Authorization", localWrite)
	allowedResponse = httptest.NewRecorder()
	router.ServeHTTP(allowedResponse, allowedDelete)
	if allowedResponse.Code != http.StatusNoContent || store.deleteCalls != 1 {
		t.Fatalf("local delete status=%d deleteCalls=%d body=%s", allowedResponse.Code, store.deleteCalls, allowedResponse.Body.String())
	}
}

func TestTenantOOBOrchestrationAuthorityRejectsForeignTokensBeforeService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.JwtSecret = "legacy-secret"
	calls := 0
	service := &fakeUserService{sendOobForTenantFn: func(_ context.Context, tenantID string, req domain.SendOobReq) (*domain.SendOobTenantResp, error) {
		calls++
		return &domain.SendOobTenantResp{
			Kind: "tikti#SendOobResponse", Email: req.Email, RequestType: req.RequestType, ExpiresIn: 900, OobCode: tenantID + "-code",
		}, nil
	}}
	router := gin.New()
	router.POST("/tenants/:tenantId/oob/send", RequireTenantOOBOrchestratorAuthority(cfg), NewOobDispatchController(service).Handle)
	bearer := func(claims jwt.MapClaims) string {
		return "Bearer " + signRoleAccessToken(t, key, claims)
	}
	localRead := bearer(jwt.MapClaims{"sub": "reader", "scope": tenantIdentityReadScope, "tid": "bereia"})
	localWrite := bearer(jwt.MapClaims{"sub": "writer", "scope": tenantIdentityWriteScope, "tid": "bereia"})
	foreignWrite := bearer(jwt.MapClaims{"sub": "writer", "scope": tenantIdentityWriteScope, "tid": "storifly"})
	platformWithoutProvenance := bearer(jwt.MapClaims{
		"sub": "platform", "scope": platformTenantAdminScope, "tid": "home", "role": string(domain.RoleAdmin),
	})
	body := `{"requestType":"EMAIL_SIGNIN","email":"u@example.com"}`
	for _, test := range []struct {
		name, authorization string
		want                int
	}{
		{name: "missing bearer", want: http.StatusUnauthorized},
		{name: "foreign bearer", authorization: foreignWrite, want: http.StatusForbidden},
		{name: "read-only bearer", authorization: localRead, want: http.StatusForbidden},
		{name: "platform without provenance", authorization: platformWithoutProvenance, want: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := calls
			request := httptest.NewRequest(http.MethodPost, "/tenants/bereia/oob/send", strings.NewReader(body))
			request.Header.Set("Authorization", test.authorization)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.want || calls != before {
				t.Fatalf("status=%d want=%d calls=%d wantCalls=%d body=%s", response.Code, test.want, calls, before, response.Body.String())
			}
		})
	}

	request := httptest.NewRequest(http.MethodPost, "/tenants/bereia/oob/send", strings.NewReader(body))
	request.Header.Set("Authorization", localWrite)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || calls != 1 || response.Header().Get(oobDeliveryContractHeader) != "external-required" {
		t.Fatalf("allowed status=%d calls=%d headers=%v body=%s", response.Code, calls, response.Header(), response.Body.String())
	}
}
