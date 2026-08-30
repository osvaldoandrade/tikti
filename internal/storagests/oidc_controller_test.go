package storagests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type oidcJWKSProvider struct {
	jwks map[string]any
	err  error
}

func (p oidcJWKSProvider) JWKS(context.Context) (map[string]any, error) {
	return p.jwks, p.err
}

func TestOIDCControllerPublishesOnlyReviewedMachineMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)
	controller := NewOIDCController(
		"https://tikti.example.com/",
		"http://tikti.code-admin.svc:8080/internal/v1/storage/jwks.json",
		oidcJWKSProvider{},
	)
	engine := gin.New()
	engine.GET(MachineOIDCDiscoveryPath, controller.Discovery)

	request := httptest.NewRequest(http.MethodGet, MachineOIDCDiscoveryPath, nil)
	request.Header.Set("Origin", "https://console.example.com")
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "public, max-age=300" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var document map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document) != 4 || document["issuer"] != "https://tikti.example.com" ||
		document["jwks_uri"] != "http://tikti.code-admin.svc:8080/internal/v1/storage/jwks.json" {
		t.Fatalf("unexpected discovery document: %#v", document)
	}
	for _, forbidden := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "response_types_supported"} {
		if _, exists := document[forbidden]; exists {
			t.Fatalf("interactive field %q was advertised", forbidden)
		}
	}
	wantClaims := make([]any, len(storageOIDCClaims))
	for index, claim := range storageOIDCClaims {
		wantClaims[index] = claim
	}
	if !reflect.DeepEqual(document["claims_supported"], wantClaims) {
		t.Fatalf("claims_supported=%#v", document["claims_supported"])
	}
}

func TestOIDCControllerReusesExistingJWKSAndFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name       string
		provider   oidcJWKSProvider
		wantStatus int
	}{
		{name: "success", provider: oidcJWKSProvider{jwks: map[string]any{"keys": []any{map[string]any{"kid": "storage-key"}}}}, wantStatus: http.StatusOK},
		{name: "unavailable", provider: oidcJWKSProvider{err: errors.New("sentinel provider failure")}, wantStatus: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller := NewOIDCController("https://tikti.example.com", "https://tikti.example.com/internal/v1/storage/jwks.json", test.provider)
			engine := gin.New()
			engine.GET(MachineOIDCJWKSPath, controller.JWKS)
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, httptest.NewRequest(http.MethodGet, MachineOIDCJWKSPath, nil))
			if response.Code != test.wantStatus || response.Header().Get("Cache-Control") != "public, max-age=300" ||
				response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
			if test.wantStatus != http.StatusOK && strings.Contains(response.Body.String(), "sentinel") {
				t.Fatalf("provider error leaked: %s", response.Body.String())
			}
		})
	}
}
