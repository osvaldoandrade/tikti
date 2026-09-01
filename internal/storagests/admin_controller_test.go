package storagests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type adminControllerBroker struct {
	list     AdminListRequest
	upload   AdminUploadRequest
	download AdminDownloadRequest
	delete   AdminDeleteRequest
	token    string
}

func (b *adminControllerBroker) List(_ context.Context, request AdminListRequest, token, _ string) (AdminObjectList, *Error) {
	b.list, b.token = request, token
	return AdminObjectList{SchemaVersion: AdminObjectStorageVersion, Prefix: request.Prefix, Items: []AdminObject{}}, nil
}
func (b *adminControllerBroker) CreateUploadURL(_ context.Context, request AdminUploadRequest, token, _ string) (AdminSignedURL, *Error) {
	b.upload, b.token = request, token
	return AdminSignedURL{URL: "https://s3.example.com/bucket/key?signed=1", Method: http.MethodPut, ExpiresIn: 60, Headers: map[string]string{"Content-Type": request.ContentType}}, nil
}
func (b *adminControllerBroker) CreateDownloadURL(_ context.Context, request AdminDownloadRequest, token, _ string) (AdminSignedURL, *Error) {
	b.download, b.token = request, token
	return AdminSignedURL{URL: "https://s3.example.com/bucket/key?signed=1", Method: http.MethodGet, ExpiresIn: 60}, nil
}
func (b *adminControllerBroker) Delete(_ context.Context, request AdminDeleteRequest, token, _ string) *Error {
	b.delete, b.token = request, token
	return nil
}

func TestAdminControllerRoutesAreExactStrictAndNonCacheable(t *testing.T) {
	t.Parallel()
	broker := &adminControllerBroker{}
	controller := NewAdminController(broker)
	engine := httptest.NewServer(adminControllerEngine(controller))
	defer engine.Close()

	client := engine.Client()
	for _, test := range []struct {
		method, path, body string
	}{
		{method: http.MethodGet, path: "/v1/admin/tenants/payments/storage/buckets/invoices/objects?prefix=reports%2F&pageSize=25&pageToken=opaque&include=object-delete-v1"},
		{method: http.MethodPost, path: "/v1/admin/tenants/payments/storage/buckets/invoices/objects/upload-url", body: `{"key":"reports/a.txt","size":12,"contentType":"text/plain"}`},
		{method: http.MethodPost, path: "/v1/admin/tenants/payments/storage/buckets/invoices/objects/download-url", body: `{"key":"reports/a.txt"}`},
		{method: http.MethodPost, path: "/v1/admin/tenants/payments/storage/buckets/invoices/objects:delete", body: `{"key":"reports/a.txt","etag":"\"etag\""}`},
	} {
		request, _ := http.NewRequest(test.method, engine.URL+test.path, strings.NewReader(test.body))
		request.Header.Set("Authorization", "Bearer opaque-access-token-value")
		request.Header.Set("X-Request-Id", "request-1")
		if test.body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		want := http.StatusOK
		if strings.HasSuffix(test.path, "objects:delete") {
			want = http.StatusNoContent
		}
		if response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" {
			t.Fatalf("path=%s status=%d headers=%v", test.path, response.StatusCode, response.Header)
		}
	}
	if broker.list.TenantID != "payments" || broker.list.BucketID != "invoices" || broker.list.Prefix != "reports/" || broker.list.PageSize != 25 || broker.list.PageToken != "opaque" || !broker.list.IncludeDeleteMetadata ||
		broker.upload.Key != "reports/a.txt" || broker.upload.Size != 12 || broker.download.Key != "reports/a.txt" || broker.delete.Key != "reports/a.txt" || broker.delete.ETag != `"etag"` || broker.token != "opaque-access-token-value" {
		t.Fatalf("list=%#v upload=%#v download=%#v delete=%#v token=%q", broker.list, broker.upload, broker.download, broker.delete, broker.token)
	}
}

func TestAdminControllerRejectsBearerAliasesAndUnknownJSON(t *testing.T) {
	t.Parallel()
	broker := &adminControllerBroker{}
	server := httptest.NewServer(adminControllerEngine(NewAdminController(broker)))
	defer server.Close()
	for _, test := range []struct {
		name, authorization, body string
		want                      int
	}{
		{name: "missing bearer", body: `{"key":"a.txt","size":1,"contentType":"text/plain"}`, want: http.StatusUnauthorized},
		{name: "unknown JSON", authorization: "Bearer opaque-access-token-value", body: `{"key":"a.txt","size":1,"contentType":"text/plain","credential":"forbidden"}`, want: http.StatusBadRequest},
	} {
		request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/admin/tenants/payments/storage/buckets/invoices/objects/upload-url", strings.NewReader(test.body))
		request.Header.Set("Authorization", test.authorization)
		request.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != test.want || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s status=%d headers=%v", test.name, response.StatusCode, response.Header)
		}
	}
}

func adminControllerEngine(controller *AdminController) http.Handler {
	engine := gin.New()
	base := "/v1/admin/tenants/:tenantId/storage/buckets/:bucketId"
	engine.GET(base+"/objects", controller.List)
	engine.POST(base+"/objects/upload-url", controller.UploadURL)
	engine.POST(base+"/objects/download-url", controller.DownloadURL)
	engine.POST(base+"/objects:delete", controller.Delete)
	return engine
}
