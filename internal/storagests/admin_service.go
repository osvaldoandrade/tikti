package storagests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	adminReadScope  = "code-admin:storage:read"
	adminWriteScope = "code-admin:storage:write"
	adminPresignTTL = 60
)

type AdminService struct {
	verifier                   AdminAccessTokenValidator
	signer                     AdminAssertionSigner
	authorizer                 AdminAuthorizer
	issuer                     CredentialIssuer
	objects                    AdminObjectOperator
	tokenIssuer, tokenAudience string
	cohort                     map[string]struct{}
	semaphore                  chan struct{}
	now                        func() time.Time
}

func NewAdminService(
	verifier AdminAccessTokenValidator,
	signer AdminAssertionSigner,
	authorizer AdminAuthorizer,
	issuer CredentialIssuer,
	objects AdminObjectOperator,
	tokenIssuer, tokenAudience string,
	cohortTenants []string,
	maximumConcurrent int,
) (*AdminService, error) {
	if verifier == nil || signer == nil || authorizer == nil || issuer == nil || objects == nil ||
		!validHTTPSIssuer(tokenIssuer) || strings.TrimSpace(tokenAudience) == "" || len(tokenAudience) > 128 ||
		len(cohortTenants) == 0 || maximumConcurrent < 1 || maximumConcurrent > 32 {
		return nil, ErrInvalidDependencyResponse
	}
	cohort := make(map[string]struct{}, len(cohortTenants))
	for _, tenantID := range cohortTenants {
		if !validDNSLabel(tenantID) {
			return nil, ErrInvalidDependencyResponse
		}
		cohort[tenantID] = struct{}{}
	}
	return &AdminService{
		verifier: verifier, signer: signer, authorizer: authorizer, issuer: issuer, objects: objects,
		tokenIssuer: strings.TrimSuffix(tokenIssuer, "/"), tokenAudience: tokenAudience,
		cohort: cohort, semaphore: make(chan struct{}, maximumConcurrent), now: time.Now,
	}, nil
}

func (s *AdminService) List(ctx context.Context, request AdminListRequest, accessToken, requestID string) (AdminObjectList, *Error) {
	if request.PageSize < 1 || request.PageSize > 200 || len(request.PageToken) > 2048 || !validAdminPrefix(request.Prefix) {
		return AdminObjectList{}, adminPublicError(http.StatusBadRequest, CodeInvalidParameterValue, "invalid_request", "The object list request is invalid.")
	}
	approval, credentials, publicErr := s.authorize(ctx, request.TenantID, request.BucketID, AdminOperationList, adminReadScope, accessToken, requestID)
	if publicErr != nil {
		return AdminObjectList{}, publicErr
	}
	result, err := s.objects.ListObjects(ctx, approval.Decision.Bucket.ProviderBucketName, request.Prefix, request.PageSize, request.PageToken, approval.Decision.Bucket.Region, credentials)
	if err != nil || result.SchemaVersion != AdminObjectStorageVersion || result.Prefix != request.Prefix || len(result.Items) > request.PageSize || len(result.NextPageToken) > 2048 {
		return AdminObjectList{}, adminPublicError(http.StatusServiceUnavailable, CodeServiceUnavailable, "provider_unavailable", "Object storage is temporarily unavailable.")
	}
	return result, nil
}

func (s *AdminService) CreateUploadURL(ctx context.Context, request AdminUploadRequest, accessToken, requestID string) (AdminSignedURL, *Error) {
	if !validAdminObjectKey(request.Key) || request.Size < 1 || !validAdminContentType(request.ContentType) {
		return AdminSignedURL{}, adminPublicError(http.StatusBadRequest, CodeInvalidParameterValue, "invalid_request", "The upload request is invalid.")
	}
	approval, credentials, publicErr := s.authorize(ctx, request.TenantID, request.BucketID, AdminOperationUpload, adminWriteScope, accessToken, requestID)
	if publicErr != nil {
		return AdminSignedURL{}, publicErr
	}
	if request.Size > approval.Decision.MaximumUploadBytes {
		return AdminSignedURL{}, adminPublicError(http.StatusRequestEntityTooLarge, CodeInvalidParameterValue, "upload_too_large", "The object exceeds the administrative upload limit.")
	}
	if approval.Decision.Policy != ReadWriteAccess {
		return AdminSignedURL{}, adminPublicError(http.StatusForbidden, CodeAccessDenied, "access_denied", "Access is denied.")
	}
	result, err := s.objects.Presign(
		s.now(), approval.Decision.Bucket.Endpoint, approval.Decision.Bucket.ProviderBucketName,
		request.Key, request.ContentType, http.MethodPut, approval.Decision.Bucket.Region,
		approval.Decision.MaximumPresignTTLSeconds, credentials,
	)
	if err != nil || !validAdminSignedURL(result, http.MethodPut, request.ContentType) {
		return AdminSignedURL{}, adminPublicError(http.StatusServiceUnavailable, CodeServiceUnavailable, "provider_unavailable", "Object storage is temporarily unavailable.")
	}
	return result, nil
}

func (s *AdminService) CreateDownloadURL(ctx context.Context, request AdminDownloadRequest, accessToken, requestID string) (AdminSignedURL, *Error) {
	if !validAdminObjectKey(request.Key) {
		return AdminSignedURL{}, adminPublicError(http.StatusBadRequest, CodeInvalidParameterValue, "invalid_request", "The download request is invalid.")
	}
	approval, credentials, publicErr := s.authorize(ctx, request.TenantID, request.BucketID, AdminOperationDownload, adminReadScope, accessToken, requestID)
	if publicErr != nil {
		return AdminSignedURL{}, publicErr
	}
	result, err := s.objects.Presign(
		s.now(), approval.Decision.Bucket.Endpoint, approval.Decision.Bucket.ProviderBucketName,
		request.Key, "", http.MethodGet, approval.Decision.Bucket.Region,
		approval.Decision.MaximumPresignTTLSeconds, credentials,
	)
	if err != nil || !validAdminSignedURL(result, http.MethodGet, "") {
		return AdminSignedURL{}, adminPublicError(http.StatusServiceUnavailable, CodeServiceUnavailable, "provider_unavailable", "Object storage is temporarily unavailable.")
	}
	return result, nil
}

func (s *AdminService) authorize(
	ctx context.Context,
	tenantID, bucketID string,
	operation AdminOperation,
	requiredScope, accessToken, requestID string,
) (AdminApproval, Credentials, *Error) {
	if s == nil || !validDNSLabel(tenantID) || !validDNSLabel(bucketID) || !opaqueIDPattern.MatchString(requestID) ||
		len(accessToken) < 16 || len(accessToken) > 16<<10 {
		return AdminApproval{}, Credentials{}, adminPublicError(http.StatusBadRequest, CodeInvalidParameterValue, "invalid_request", "The object storage request is invalid.")
	}
	if _, enabled := s.cohort[tenantID]; !enabled {
		return AdminApproval{}, Credentials{}, adminPublicError(http.StatusNotFound, CodeAccessDenied, "not_found", "The bucket was not found.")
	}
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	default:
		return AdminApproval{}, Credentials{}, adminPublicError(http.StatusTooManyRequests, CodeThrottling, "throttled", "The request rate is too high.")
	}
	claims, err := s.verifier.ValidateAccessToken(ctx, accessToken, s.tokenIssuer, s.tokenAudience)
	if err != nil {
		return AdminApproval{}, Credentials{}, adminPublicError(http.StatusUnauthorized, CodeInvalidIdentityToken, "invalid_token", "The access token is invalid.")
	}
	actor, _ := claims["sub"].(string)
	claimTenant, _ := claims["tid"].(string)
	scopeText, _ := claims["scope"].(string)
	if actor == "" || len(actor) > 253 || actor != strings.TrimSpace(actor) || claimTenant != tenantID ||
		!slices.Contains(strings.Fields(scopeText), requiredScope) {
		return AdminApproval{}, Credentials{}, adminPublicError(http.StatusForbidden, CodeAccessDenied, "access_denied", "Access is denied.")
	}
	serviceAssertion, err := s.signer.SignServiceAssertion(s.now())
	if err != nil {
		return AdminApproval{}, Credentials{}, adminPublicError(http.StatusServiceUnavailable, CodeServiceUnavailable, "identity_unavailable", "Object storage is temporarily unavailable.")
	}
	digest := sha256.Sum256([]byte(accessToken))
	decision, err := s.authorizer.AuthorizeAdmin(ctx, AdminAuthorizationRequest{
		SchemaVersion: AdminObjectStorageVersion, TenantID: tenantID, BucketID: bucketID, Operation: operation,
		ActorSubject: actor, AccessTokenSHA256: hex.EncodeToString(digest[:]),
		RequestedCredentialTTLSeconds: defaultCredentialTTL, RequestedPresignTTLSeconds: adminPresignTTL,
		RequestID: requestID,
	}, serviceAssertion)
	if err != nil {
		return AdminApproval{}, Credentials{}, adminPublicError(http.StatusServiceUnavailable, CodeServiceUnavailable, "authorizer_unavailable", "Object storage is temporarily unavailable.")
	}
	if !validAdminAuthorizationDecision(decision, operation) {
		if !decision.Allowed && validAdminDenyDecision(decision) {
			status := http.StatusForbidden
			if decision.Reason == "BucketNotReady" || decision.Reason == "CohortDisabled" {
				status = http.StatusNotFound
			}
			return AdminApproval{}, Credentials{}, adminPublicError(status, CodeAccessDenied, "access_denied", "Access is denied.")
		}
		return AdminApproval{}, Credentials{}, adminPublicError(http.StatusServiceUnavailable, CodeServiceUnavailable, "authorizer_invalid", "Object storage is temporarily unavailable.")
	}
	wantedPolicy := ReadOnlyAccess
	if operation == AdminOperationUpload {
		wantedPolicy = ReadWriteAccess
	}
	if decision.Policy != wantedPolicy {
		return AdminApproval{}, Credentials{}, adminPublicError(http.StatusForbidden, CodeAccessDenied, "access_denied", "Access is denied.")
	}
	approval := AdminApproval{ActorSubject: actor, TenantID: tenantID, Operation: operation, Decision: decision}
	minioAssertion, err := s.signer.SignAdminMinIOAssertion(s.now(), approval)
	if err != nil {
		return AdminApproval{}, Credentials{}, adminPublicError(http.StatusServiceUnavailable, CodeServiceUnavailable, "identity_unavailable", "Object storage is temporarily unavailable.")
	}
	credentials, err := s.issuer.Exchange(ctx, minioAssertion, defaultCredentialTTL)
	if err != nil || !validIssuedCredentials(credentials, s.now(), defaultCredentialTTL) {
		return AdminApproval{}, Credentials{}, adminPublicError(http.StatusServiceUnavailable, CodeServiceUnavailable, "provider_unavailable", "Object storage is temporarily unavailable.")
	}
	return approval, credentials, nil
}

func validAdminAuthorizationDecision(decision AdminAuthorizationDecision, _ AdminOperation) bool {
	if !decision.Allowed || decision.SchemaVersion != AdminObjectStorageVersion || decision.Reason != "Allowed" || decision.Bucket == nil ||
		decision.MaximumCredentialTTLSeconds != defaultCredentialTTL || decision.MaximumPresignTTLSeconds != adminPresignTTL ||
		decision.MaximumUploadBytes < 1 || decision.MaximumUploadBytes > 5<<30 ||
		!opaqueIDPattern.MatchString(decision.Bucket.UID) || decision.Bucket.Generation < 1 ||
		decision.Bucket.ObservedGeneration != decision.Bucket.Generation ||
		!physicalNamePattern.MatchString(decision.Bucket.ProviderBucketName) || !exactHTTPSOrigin(decision.Bucket.Endpoint) ||
		!regionPattern.MatchString(decision.Bucket.Region) {
		return false
	}
	return decision.Policy == ReadOnlyAccess || decision.Policy == ReadWriteAccess
}

func validAdminDenyDecision(decision AdminAuthorizationDecision) bool {
	if decision.SchemaVersion != AdminObjectStorageVersion || decision.Allowed || decision.Bucket != nil || decision.Policy != "" ||
		decision.MaximumCredentialTTLSeconds != 0 || decision.MaximumPresignTTLSeconds != 0 || decision.MaximumUploadBytes != 0 {
		return false
	}
	switch decision.Reason {
	case "InvalidRequest", "BucketNotReady", "InstallationNotReady", "CohortDisabled", "DependencyUnavailable":
		return true
	default:
		return false
	}
}

func validAdminObjectKey(value string) bool {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.HasPrefix(value, "/") ||
		strings.HasSuffix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	for _, character := range value {
		if character == 0 || character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validAdminPrefix(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 1024 || !utf8.ValidString(value) || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	return validAdminObjectKey(strings.TrimSuffix(value, "/"))
}

func validAdminContentType(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 255 {
		return false
	}
	_, _, err := mime.ParseMediaType(value)
	return err == nil
}

func validAdminSignedURL(result AdminSignedURL, method, contentType string) bool {
	if result.Method != method || result.ExpiresIn != adminPresignTTL || !strings.HasPrefix(result.URL, "https://") || !strings.Contains(result.URL, "?") {
		return false
	}
	if method == http.MethodGet {
		return len(result.Headers) == 0
	}
	return len(result.Headers) == 1 && result.Headers["Content-Type"] == contentType
}

func adminPublicError(status int, code Code, reason, message string) *Error {
	return &Error{Code: code, HTTPStatus: status, Reason: closedReason(reason), Message: message}
}
