package app

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
	"github.com/osvaldoandrade/tikti/pkg/config"
)

type samlRouteCountingStore struct {
	saml.Store
	getCalls    int
	putCalls    int
	deleteCalls int
}

func (s *samlRouteCountingStore) GetIdP(context.Context, string) (saml.IdPRecord, error) {
	s.getCalls++
	return saml.IdPRecord{}, saml.ErrIdPNotFound
}

func (s *samlRouteCountingStore) PutIdP(context.Context, saml.IdPRecord) error {
	s.putCalls++
	return nil
}

func (s *samlRouteCountingStore) DeleteIdP(context.Context, string) error {
	s.deleteCalls++
	return nil
}

func (s *samlRouteCountingStore) calls() int {
	return s.getCalls + s.putCalls + s.deleteCalls
}

func TestSAMLAdminRoutesRejectForeignAuthorityBeforeStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	privateKey := applicationTestPrivateKey(t, 2048)
	cfg := &config.Config{
		ApiKey: "server-key", JwksPrivateKey: privateKey,
		IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin", JwtSecret: "legacy-secret",
	}
	store := &samlRouteCountingStore{}
	router := gin.New()
	SetupMappings(router, cfg, nil, nil, nil, nil, nil, nil, nil, store, nil)
	bearer := func(claims jwt.MapClaims) string {
		return "Bearer " + applicationRoleToken(t, privateKey, claims)
	}
	localRead := bearer(jwt.MapClaims{"sub": "reader", "scope": "code-admin:identity:read", "tid": "bereia"})
	localWrite := bearer(jwt.MapClaims{"sub": "writer", "scope": "code-admin:identity:write", "tid": "bereia"})
	foreignWrite := bearer(jwt.MapClaims{"sub": "writer", "scope": "code-admin:identity:write", "tid": "storifly"})
	hsToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "legacy", "scope": "code-admin:identity:write", "tid": "bereia", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(cfg.JwtSecret))
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name, method, target, apiKey, authorization string
		want                                        int
	}{
		{name: "missing service key", method: http.MethodGet, target: "/v1/admin/tenants/bereia/saml/idp", authorization: localRead, want: http.StatusUnauthorized},
		{name: "query service key", method: http.MethodGet, target: "/v1/admin/tenants/bereia/saml/idp?key=server-key", authorization: localRead, want: http.StatusUnauthorized},
		{name: "missing bearer", method: http.MethodGet, target: "/v1/admin/tenants/bereia/saml/idp", apiKey: "server-key", want: http.StatusUnauthorized},
		{name: "legacy bearer", method: http.MethodDelete, target: "/v1/admin/tenants/bereia/saml/idp", apiKey: "server-key", authorization: "Bearer " + hsToken, want: http.StatusUnauthorized},
		{name: "foreign read", method: http.MethodGet, target: "/v1/admin/tenants/bereia/saml/idp", apiKey: "server-key", authorization: foreignWrite, want: http.StatusForbidden},
		{name: "foreign write", method: http.MethodPut, target: "/v1/admin/tenants/bereia/saml/idp", apiKey: "server-key", authorization: foreignWrite, want: http.StatusForbidden},
		{name: "foreign delete", method: http.MethodDelete, target: "/v1/admin/tenants/bereia/saml/idp", apiKey: "server-key", authorization: foreignWrite, want: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := store.calls()
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(`{"metadataXml":"ignored"}`))
			request.Header.Set("X-API-Key", test.apiKey)
			request.Header.Set("Authorization", test.authorization)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
			if store.calls() != before {
				t.Fatalf("denied route reached SAML store: before=%d after=%d", before, store.calls())
			}
		})
	}

	allowedRead := httptest.NewRequest(http.MethodGet, "/v1/admin/tenants/bereia/saml/idp", nil)
	allowedRead.Header.Set("X-API-Key", "server-key")
	allowedRead.Header.Set("Authorization", localRead)
	allowedResponse := httptest.NewRecorder()
	router.ServeHTTP(allowedResponse, allowedRead)
	if allowedResponse.Code != http.StatusOK || store.getCalls != 1 {
		t.Fatalf("allowed read status=%d getCalls=%d body=%s", allowedResponse.Code, store.getCalls, allowedResponse.Body.String())
	}

	allowedDelete := httptest.NewRequest(http.MethodDelete, "/v1/admin/tenants/bereia/saml/idp", nil)
	allowedDelete.Header.Set("X-API-Key", "server-key")
	allowedDelete.Header.Set("Authorization", localWrite)
	allowedResponse = httptest.NewRecorder()
	router.ServeHTTP(allowedResponse, allowedDelete)
	if allowedResponse.Code != http.StatusNoContent || store.deleteCalls != 1 {
		t.Fatalf("allowed delete status=%d deleteCalls=%d body=%s", allowedResponse.Code, store.deleteCalls, allowedResponse.Body.String())
	}
}
