package storagests

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const AdminObjectStorageVersion = "object-storage-admin.v1"

type AdminOperation string

const (
	AdminOperationList     AdminOperation = "List"
	AdminOperationUpload   AdminOperation = "Upload"
	AdminOperationDownload AdminOperation = "Download"
)

type AdminAuthorizationRequest struct {
	SchemaVersion                 string         `json:"schemaVersion"`
	TenantID                      string         `json:"tenantId"`
	BucketID                      string         `json:"bucketId"`
	Operation                     AdminOperation `json:"operation"`
	ActorSubject                  string         `json:"actorSubject"`
	AccessTokenSHA256             string         `json:"accessTokenSha256"`
	RequestedCredentialTTLSeconds int            `json:"requestedCredentialTtlSeconds"`
	RequestedPresignTTLSeconds    int            `json:"requestedPresignTtlSeconds"`
	RequestID                     string         `json:"requestId"`
}

type AdminAuthorizationBucket struct {
	UID                string `json:"uid"`
	Generation         int64  `json:"generation"`
	ObservedGeneration int64  `json:"observedGeneration"`
	ProviderBucketName string `json:"providerBucketName"`
	Endpoint           string `json:"endpoint"`
	Region             string `json:"region"`
}

type AdminAuthorizationDecision struct {
	SchemaVersion               string                    `json:"schemaVersion"`
	Allowed                     bool                      `json:"allowed"`
	Reason                      string                    `json:"reason"`
	Policy                      string                    `json:"policy,omitempty"`
	Bucket                      *AdminAuthorizationBucket `json:"bucket,omitempty"`
	MaximumCredentialTTLSeconds int                       `json:"maximumCredentialTtlSeconds,omitempty"`
	MaximumPresignTTLSeconds    int                       `json:"maximumPresignTtlSeconds,omitempty"`
	MaximumUploadBytes          int64                     `json:"maximumUploadBytes,omitempty"`
}

type AdminApproval struct {
	ActorSubject string
	TenantID     string
	Operation    AdminOperation
	Decision     AdminAuthorizationDecision
}

type AdminObject struct {
	Key          string `json:"key"`
	Kind         string `json:"kind"`
	Size         int64  `json:"size,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

type AdminObjectList struct {
	SchemaVersion string        `json:"schemaVersion"`
	Prefix        string        `json:"prefix,omitempty"`
	Items         []AdminObject `json:"items"`
	NextPageToken string        `json:"nextPageToken,omitempty"`
}

type AdminSignedURL struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	ExpiresIn int               `json:"expiresIn"`
	Headers   map[string]string `json:"headers,omitempty"`
}

type AdminListRequest struct {
	TenantID, BucketID, Prefix, PageToken string
	PageSize                              int
}

type AdminUploadRequest struct {
	TenantID, BucketID, Key, ContentType string
	Size                                 int64
}

type AdminDownloadRequest struct {
	TenantID, BucketID, Key string
}

type AdminAccessTokenValidator interface {
	ValidateAccessToken(context.Context, string, string, string) (jwt.MapClaims, error)
}

type AdminAssertionSigner interface {
	SignServiceAssertion(time.Time) (string, error)
	SignAdminMinIOAssertion(time.Time, AdminApproval) (string, error)
}

type AdminAuthorizer interface {
	AuthorizeAdmin(context.Context, AdminAuthorizationRequest, string) (AdminAuthorizationDecision, error)
}

type AdminObjectOperator interface {
	ListObjects(context.Context, string, string, int, string, string, Credentials) (AdminObjectList, error)
	Presign(time.Time, string, string, string, string, string, string, int, Credentials) (AdminSignedURL, error)
}
