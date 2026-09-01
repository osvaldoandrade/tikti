package storagests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type adminTokenVerifier struct {
	claims jwt.MapClaims
	err    error
}

func (v adminTokenVerifier) ValidateAccessToken(context.Context, string, string, string) (jwt.MapClaims, error) {
	return v.claims, v.err
}

type adminTestSigner struct{}

func (adminTestSigner) SignServiceAssertion(time.Time) (string, error) {
	return "service-assertion", nil
}
func (adminTestSigner) SignAdminMinIOAssertion(time.Time, AdminApproval) (string, error) {
	return "minio-assertion", nil
}

type adminTestAuthorizer struct {
	request AdminAuthorizationRequest
	result  AdminAuthorizationDecision
	err     error
}

func (a *adminTestAuthorizer) AuthorizeAdmin(_ context.Context, request AdminAuthorizationRequest, assertion string) (AdminAuthorizationDecision, error) {
	if assertion != "service-assertion" {
		return AdminAuthorizationDecision{}, errors.New("unexpected service assertion")
	}
	a.request = request
	return a.result, a.err
}

type adminCredentialIssuer struct {
	assertion string
}

func (i *adminCredentialIssuer) Exchange(_ context.Context, assertion string, duration int) (Credentials, error) {
	i.assertion = assertion
	if duration != 900 {
		return Credentials{}, errors.New("unexpected duration")
	}
	return Credentials{AccessKeyID: strings.Repeat("a", 20), SecretAccessKey: strings.Repeat("b", 40), SessionToken: strings.Repeat("c", 32), Expiration: time.Now().Add(15 * time.Minute)}, nil
}

type adminObjectOperator struct {
	bucket, prefix, key, contentType, method string
	etag                                     string
	pageSize                                 int
	credentials                              Credentials
	deleteErr                                error
}

func (o *adminObjectOperator) ListObjects(_ context.Context, bucket, prefix string, pageSize int, _ string, _ string, credentials Credentials) (AdminObjectList, error) {
	o.bucket, o.prefix, o.pageSize, o.credentials = bucket, prefix, pageSize, credentials
	return AdminObjectList{SchemaVersion: AdminObjectStorageVersion, Prefix: prefix, Items: []AdminObject{{Key: "reports/", Kind: "prefix"}, {Key: "readme.txt", Kind: "object", Size: 12, ETag: `"etag"`}}}, nil
}

func (o *adminObjectOperator) Presign(_ time.Time, endpoint, bucket, key, contentType, method, region string, ttl int, credentials Credentials) (AdminSignedURL, error) {
	o.bucket, o.key, o.contentType, o.method, o.credentials = bucket, key, contentType, method, credentials
	if endpoint != "https://s3.example.com" || region != "us-central1" || ttl != 60 {
		return AdminSignedURL{}, errors.New("unexpected signing inputs")
	}
	result := AdminSignedURL{URL: endpoint + "/" + bucket + "/" + key + "?opaque=1", Method: method, ExpiresIn: ttl}
	if method == http.MethodPut {
		result.Headers = map[string]string{"Content-Type": contentType}
	}
	return result, nil
}

func (o *adminObjectOperator) DeleteObject(_ context.Context, bucket, key, etag, region string, credentials Credentials) error {
	o.bucket, o.key, o.etag, o.credentials = bucket, key, etag, credentials
	if region != "us-central1" {
		return errors.New("unexpected region")
	}
	return o.deleteErr
}

func adminAllowDecision(policy string) AdminAuthorizationDecision {
	return AdminAuthorizationDecision{
		SchemaVersion: AdminObjectStorageVersion, Allowed: true, Reason: "Allowed", Policy: policy,
		Bucket: &AdminAuthorizationBucket{
			UID: "bucket-uid", Generation: 3, ObservedGeneration: 3,
			ProviderBucketName: "cf-payments-invoices-47e89ff7e282", Endpoint: "https://s3.example.com", Region: "us-central1",
		},
		MaximumCredentialTTLSeconds: 900, MaximumPresignTTLSeconds: 60, MaximumUploadBytes: 1 << 30,
	}
}

func newAdminServiceForTest(t *testing.T, scopes string, decision AdminAuthorizationDecision) (*AdminService, *adminTestAuthorizer, *adminCredentialIssuer, *adminObjectOperator) {
	t.Helper()
	authorizer := &adminTestAuthorizer{result: decision}
	issuer := &adminCredentialIssuer{}
	operator := &adminObjectOperator{}
	service, err := NewAdminServiceWithDelete(
		adminTokenVerifier{claims: jwt.MapClaims{"sub": "user-1", "tid": "payments", "scope": scopes}},
		adminTestSigner{}, authorizer, issuer, operator,
		"https://tikti.example.com", "code-admin-api", []string{"payments"}, []string{"payments"}, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	return service, authorizer, issuer, operator
}

func TestAdminServiceDeletesOnlyTheListedCurrentObjectWithWriteAuthority(t *testing.T) {
	t.Parallel()
	service, authorizer, _, operator := newAdminServiceForTest(
		t, "code-admin:storage:read code-admin:storage:write", adminAllowDecision(ReadWriteAccess),
	)
	publicErr := service.Delete(context.Background(), AdminDeleteRequest{
		TenantID: "payments", BucketID: "invoices", Key: "reports/a.txt", ETag: `"etag"`,
	}, "opaque-access-token-value", "request-delete-1")
	if publicErr != nil || authorizer.request.Operation != AdminOperationDelete ||
		operator.bucket != "cf-payments-invoices-47e89ff7e282" || operator.key != "reports/a.txt" || operator.etag != `"etag"` {
		t.Fatalf("error=%#v authorization=%#v operator=%#v", publicErr, authorizer.request, operator)
	}

	service, _, _, _ = newAdminServiceForTest(t, "code-admin:storage:read", adminAllowDecision(ReadWriteAccess))
	publicErr = service.Delete(context.Background(), AdminDeleteRequest{
		TenantID: "payments", BucketID: "invoices", Key: "reports/a.txt", ETag: `"etag"`,
	}, "opaque-access-token-value", "request-delete-2")
	if publicErr == nil || publicErr.HTTPStatus != http.StatusForbidden {
		t.Fatalf("missing write error=%#v", publicErr)
	}
}

func TestAdminServiceMapsChangedObjectAndRejectsWeakETag(t *testing.T) {
	t.Parallel()
	service, _, _, operator := newAdminServiceForTest(
		t, "code-admin:storage:write", adminAllowDecision(ReadWriteAccess),
	)
	operator.deleteErr = ErrAdminObjectChanged
	publicErr := service.Delete(context.Background(), AdminDeleteRequest{
		TenantID: "payments", BucketID: "invoices", Key: "a.txt", ETag: `"etag"`,
	}, "opaque-access-token-value", "request-delete-3")
	if publicErr == nil || publicErr.HTTPStatus != http.StatusConflict || publicErr.Reason != "object_changed" {
		t.Fatalf("changed error=%#v", publicErr)
	}
	publicErr = service.Delete(context.Background(), AdminDeleteRequest{
		TenantID: "payments", BucketID: "invoices", Key: "a.txt", ETag: `W/"etag"`,
	}, "opaque-access-token-value", "request-delete-4")
	if publicErr == nil || publicErr.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("weak ETag error=%#v", publicErr)
	}
}

func TestAdminServiceListsAndPresignsWithoutReturningCredentials(t *testing.T) {
	t.Parallel()
	service, authorizer, issuer, operator := newAdminServiceForTest(t, "code-admin:storage:read code-admin:storage:write", adminAllowDecision(ReadOnlyAccess))
	list, publicErr := service.List(context.Background(), AdminListRequest{
		TenantID: "payments", BucketID: "invoices", Prefix: "", PageSize: 100,
	}, "opaque-access-token-value", "request-1")
	if publicErr != nil || len(list.Items) != 2 || operator.bucket != "cf-payments-invoices-47e89ff7e282" || operator.pageSize != 100 {
		t.Fatalf("list=%#v err=%v operator=%#v", list, publicErr, operator)
	}
	if authorizer.request.Operation != AdminOperationList || authorizer.request.TenantID != "payments" || authorizer.request.BucketID != "invoices" ||
		authorizer.request.ActorSubject != "user-1" || len(authorizer.request.AccessTokenSHA256) != 64 || issuer.assertion != "minio-assertion" {
		t.Fatalf("authorization=%#v assertion=%q", authorizer.request, issuer.assertion)
	}
	if list.Items[1].ETag != "" {
		t.Fatalf("legacy list leaked delete metadata: %#v", list.Items[1])
	}
	list, publicErr = service.List(context.Background(), AdminListRequest{
		TenantID: "payments", BucketID: "invoices", Prefix: "", PageSize: 100, IncludeDeleteMetadata: true,
	}, "opaque-access-token-value", "request-list-delete-metadata")
	if publicErr != nil || list.Items[1].ETag != `"etag"` {
		t.Fatalf("negotiated list=%#v err=%#v", list, publicErr)
	}

	service, authorizer, _, operator = newAdminServiceForTest(t, "code-admin:storage:read code-admin:storage:write", adminAllowDecision(ReadWriteAccess))
	upload, publicErr := service.CreateUploadURL(context.Background(), AdminUploadRequest{
		TenantID: "payments", BucketID: "invoices", Key: "reports/a.txt", Size: 12, ContentType: "text/plain",
	}, "opaque-access-token-value", "request-2")
	if publicErr != nil || upload.Method != http.MethodPut || upload.ExpiresIn != 60 || operator.key != "reports/a.txt" ||
		operator.contentType != "text/plain" || authorizer.request.Operation != AdminOperationUpload {
		t.Fatalf("upload=%#v err=%v authorization=%#v operator=%#v", upload, publicErr, authorizer.request, operator)
	}

	service, authorizer, _, operator = newAdminServiceForTest(t, "code-admin:storage:read", adminAllowDecision(ReadOnlyAccess))
	download, publicErr := service.CreateDownloadURL(context.Background(), AdminDownloadRequest{
		TenantID: "payments", BucketID: "invoices", Key: "reports/a.txt",
	}, "opaque-access-token-value", "request-3")
	if publicErr != nil || download.Method != http.MethodGet || operator.method != http.MethodGet || authorizer.request.Operation != AdminOperationDownload {
		t.Fatalf("download=%#v err=%v authorization=%#v", download, publicErr, authorizer.request)
	}
	for _, value := range []any{list, upload, download} {
		raw := strings.ToLower(strings.TrimSpace(toJSON(t, value)))
		for _, forbidden := range []string{"accesskeyid", "secretaccesskey", "sessiontoken"} {
			if strings.Contains(raw, forbidden) {
				t.Fatalf("public result contains %q: %s", forbidden, raw)
			}
		}
	}
}

func TestAdminServiceFailsClosedOnTenantScopeKeyQuotaAndDecisionMismatch(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		scopes   string
		decision AdminAuthorizationDecision
		request  AdminUploadRequest
		want     int
	}{
		{name: "missing write", scopes: "code-admin:storage:read", decision: adminAllowDecision(ReadWriteAccess), request: AdminUploadRequest{TenantID: "payments", BucketID: "invoices", Key: "a.txt", Size: 1, ContentType: "text/plain"}, want: http.StatusForbidden},
		{name: "foreign tenant", scopes: "code-admin:storage:write", decision: adminAllowDecision(ReadWriteAccess), request: AdminUploadRequest{TenantID: "identity", BucketID: "invoices", Key: "a.txt", Size: 1, ContentType: "text/plain"}, want: http.StatusNotFound},
		{name: "parent key", scopes: "code-admin:storage:write", decision: adminAllowDecision(ReadWriteAccess), request: AdminUploadRequest{TenantID: "payments", BucketID: "invoices", Key: "../a.txt", Size: 1, ContentType: "text/plain"}, want: http.StatusBadRequest},
		{name: "empty upload", scopes: "code-admin:storage:write", decision: adminAllowDecision(ReadWriteAccess), request: AdminUploadRequest{TenantID: "payments", BucketID: "invoices", Key: "a.txt", Size: 0, ContentType: "text/plain"}, want: http.StatusBadRequest},
		{name: "over quota", scopes: "code-admin:storage:write", decision: adminAllowDecision(ReadWriteAccess), request: AdminUploadRequest{TenantID: "payments", BucketID: "invoices", Key: "a.txt", Size: 1<<30 + 1, ContentType: "text/plain"}, want: http.StatusRequestEntityTooLarge},
		{name: "wrong policy", scopes: "code-admin:storage:write", decision: adminAllowDecision(ReadOnlyAccess), request: AdminUploadRequest{TenantID: "payments", BucketID: "invoices", Key: "a.txt", Size: 1, ContentType: "text/plain"}, want: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, _, _, _ := newAdminServiceForTest(t, test.scopes, test.decision)
			_, publicErr := service.CreateUploadURL(context.Background(), test.request, "opaque-access-token-value", "request-1")
			if publicErr == nil || publicErr.HTTPStatus != test.want {
				t.Fatalf("error=%#v want status=%d", publicErr, test.want)
			}
		})
	}
}

func TestAdminServiceHidesCrossTenantRequestsInsideEnabledCohort(t *testing.T) {
	t.Parallel()
	authorizer := &adminTestAuthorizer{result: adminAllowDecision(ReadWriteAccess)}
	issuer := &adminCredentialIssuer{}
	operator := &adminObjectOperator{}
	service, err := NewAdminServiceWithDelete(
		adminTokenVerifier{claims: jwt.MapClaims{
			"sub": "user-1", "tid": "payments", "scope": "code-admin:storage:write",
		}},
		adminTestSigner{}, authorizer, issuer, operator,
		"https://tikti.example.com", "code-admin-api",
		[]string{"payments", "identity"}, []string{"payments", "identity"}, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, publicErr := service.CreateUploadURL(context.Background(), AdminUploadRequest{
		TenantID: "identity", BucketID: "invoices", Key: "a.txt", Size: 1, ContentType: "text/plain",
	}, "opaque-access-token-value", "request-cross-tenant")
	if publicErr == nil || publicErr.HTTPStatus != http.StatusNotFound || authorizer.request.TenantID != "" ||
		issuer.assertion != "" || operator.key != "" {
		t.Fatalf("cross-tenant error=%#v authorizer=%#v issuer=%#v operator=%#v", publicErr, authorizer, issuer, operator)
	}
}

func toJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
