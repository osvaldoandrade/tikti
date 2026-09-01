package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/storagests"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

func TestObjectStorageBrowserRoutesAreDefaultOffExactAndAPIKeyProtected(t *testing.T) {
	t.Parallel()
	disabled := gin.New()
	setupObjectStorageBrowserMappings(disabled, &config.Config{}, nil)
	for _, route := range disabled.Routes() {
		if strings.Contains(route.Path, "/storage/buckets/") {
			t.Fatalf("default-off browser route registered: %#v", route)
		}
	}

	broker := &adminControllerBrokerAdapter{}
	controller := storagests.NewAdminController(broker)
	enabled := newSafeEngineWithWriters(&strings.Builder{}, &strings.Builder{})
	cfg := &config.Config{ApiKey: "server-key", ObjectStorageBrowser: config.ObjectStorageBrowserConfig{Enabled: true}}
	setupObjectStorageBrowserMappings(enabled, cfg, controller)

	for _, test := range []struct {
		name, method, path, apiKey, body string
		want                             int
	}{
		{name: "list", method: http.MethodGet, path: "/v1/admin/tenants/payments/storage/buckets/invoices/objects", apiKey: "server-key", want: http.StatusOK},
		{name: "upload", method: http.MethodPost, path: "/v1/admin/tenants/payments/storage/buckets/invoices/objects/upload-url", apiKey: "server-key", body: `{"key":"a.txt","size":1,"contentType":"text/plain"}`, want: http.StatusOK},
		{name: "download", method: http.MethodPost, path: "/v1/admin/tenants/payments/storage/buckets/invoices/objects/download-url", apiKey: "server-key", body: `{"key":"a.txt"}`, want: http.StatusOK},
		{name: "missing api key", method: http.MethodGet, path: "/v1/admin/tenants/payments/storage/buckets/invoices/objects", want: http.StatusUnauthorized},
		{name: "slash alias", method: http.MethodGet, path: "/v1/admin/tenants/payments/storage/buckets/invoices/objects/", apiKey: "server-key", want: http.StatusBadRequest},
		{name: "preflight", method: http.MethodOptions, path: "/v1/admin/tenants/payments/storage/buckets/invoices/objects", apiKey: "server-key", want: http.StatusBadRequest},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
		request.Header.Set("X-API-Key", test.apiKey)
		request.Header.Set("Authorization", "Bearer opaque-access-token-value")
		request.Header.Set("X-Request-Id", "request-1")
		if test.body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		enabled.ServeHTTP(response, request)
		if response.Code != test.want || response.Header().Get("Location") != "" {
			t.Fatalf("%s status=%d headers=%v body=%s", test.name, response.Code, response.Header(), response.Body.String())
		}
	}
}

type adminControllerBrokerAdapter struct{}

func (*adminControllerBrokerAdapter) List(_ context.Context, request storagests.AdminListRequest, _, _ string) (storagests.AdminObjectList, *storagests.Error) {
	return storagests.AdminObjectList{SchemaVersion: storagests.AdminObjectStorageVersion, Prefix: request.Prefix, Items: []storagests.AdminObject{}}, nil
}
func (*adminControllerBrokerAdapter) CreateUploadURL(_ context.Context, request storagests.AdminUploadRequest, _, _ string) (storagests.AdminSignedURL, *storagests.Error) {
	return storagests.AdminSignedURL{URL: "https://s3.example.com/bucket/key?signed=1", Method: http.MethodPut, ExpiresIn: 60, Headers: map[string]string{"Content-Type": request.ContentType}}, nil
}
func (*adminControllerBrokerAdapter) CreateDownloadURL(_ context.Context, _ storagests.AdminDownloadRequest, _, _ string) (storagests.AdminSignedURL, *storagests.Error) {
	return storagests.AdminSignedURL{URL: "https://s3.example.com/bucket/key?signed=1", Method: http.MethodGet, ExpiresIn: 60}, nil
}
