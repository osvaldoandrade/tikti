package storagests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type Service struct {
	verifier   ProjectedTokenVerifier
	signer     AssertionSigner
	authorizer Authorizer
	issuer     CredentialIssuer
	inflight   chan struct{}
	metrics    *Metrics
	now        func() time.Time
}

func NewService(
	verifier ProjectedTokenVerifier, signer AssertionSigner, authorizer Authorizer,
	issuer CredentialIssuer, maximumConcurrent int, metrics *Metrics,
) (*Service, error) {
	if verifier == nil || signer == nil || authorizer == nil || issuer == nil || maximumConcurrent < 1 || maximumConcurrent > 32 {
		return nil, errors.New("invalid storage STS service configuration")
	}
	return &Service{
		verifier: verifier, signer: signer, authorizer: authorizer, issuer: issuer,
		inflight: make(chan struct{}, maximumConcurrent), metrics: metrics, now: time.Now,
	}, nil
}

func (s *Service) Exchange(ctx context.Context, request Request, requestID string) (Result, *Error) {
	select {
	case s.inflight <- struct{}{}:
		if s.metrics != nil {
			s.metrics.inflight.Inc()
		}
		defer func() {
			<-s.inflight
			if s.metrics != nil {
				s.metrics.inflight.Dec()
			}
		}()
	default:
		if s.metrics != nil {
			s.metrics.throttled.Inc()
		}
		return Result{}, storageError(CodeThrottling, "throttled")
	}
	if request.DurationSeconds != defaultCredentialTTL || !validCompactJWT(request.WebIdentityToken) ||
		!opaqueIDPattern.MatchString(requestID) {
		return Result{}, storageError(CodeInvalidParameterValue, "invalid_request")
	}
	parsedRole, roleValid := parseRole(request.RoleARN, request.Role.AccountID)
	if !roleValid || parsedRole != request.Role {
		return Result{}, storageError(CodeInvalidParameterValue, "invalid_request")
	}
	identity, err := s.verifier.Verify(ctx, request.WebIdentityToken)
	if err != nil {
		if errors.Is(err, domain.ErrWorkloadTokenInvalid) {
			if s.metrics != nil {
				s.metrics.invalidToken.Inc()
			}
			return Result{}, storageError(CodeInvalidIdentityToken, "invalid_token")
		}
		return Result{}, storageError(CodeIDPCommunicationError, "authorizer_unavailable")
	}
	if !validVerifiedIdentity(identity) || identity.Namespace != request.Role.Namespace ||
		request.Role.TenantID == "" || request.Role.Namespace != "workload-"+request.Role.TenantID {
		return Result{}, storageError(CodeAccessDenied, "denied")
	}
	serviceAssertion, err := s.signer.SignServiceAssertion(s.now())
	if err != nil {
		return Result{}, storageError(CodeInternalFailure, "internal")
	}
	digest := sha256.Sum256([]byte(request.WebIdentityToken))
	authorizationRequest := AuthorizationRequest{
		SchemaVersion: ObjectStorageVersion, RoleARN: request.RoleARN, Issuer: identity.Issuer,
		ClusterRef: identity.ClusterRef, Namespace: identity.Namespace, ServiceAccount: identity.ServiceAccount,
		Subject: identity.Subject, TokenSHA256: hex.EncodeToString(digest[:]),
		RequestedDurationSeconds: request.DurationSeconds, RequestID: requestID,
	}
	authorizerStarted := time.Now()
	decision, err := s.authorizer.Authorize(ctx, authorizationRequest, serviceAssertion)
	if err != nil {
		if errors.Is(err, ErrInvalidDependencyResponse) {
			s.metrics.observeAuthorizer("error", authorizerStarted)
			return Result{}, storageError(CodeInternalFailure, "authorizer_invalid")
		}
		s.metrics.observeAuthorizer("error", authorizerStarted)
		return Result{}, storageError(CodeIDPCommunicationError, "authorizer_unavailable")
	}
	if !validAuthorizationDecision(decision) {
		s.metrics.observeAuthorizer("error", authorizerStarted)
		return Result{}, storageError(CodeInternalFailure, "authorizer_invalid")
	}
	if !decision.Allowed {
		s.metrics.observeAuthorizer("error", authorizerStarted)
		return Result{}, storageError(CodeAccessDenied, "denied")
	}
	s.metrics.observeAuthorizer("success", authorizerStarted)
	approval := Approval{Identity: identity, Role: request.Role, Decision: decision}
	minioAssertion, err := s.signer.SignMinIOAssertion(s.now(), approval)
	if err != nil {
		return Result{}, storageError(CodeInternalFailure, "internal")
	}
	minioStarted := time.Now()
	credentials, err := s.issuer.Exchange(ctx, minioAssertion, request.DurationSeconds)
	if err != nil {
		if errors.Is(err, ErrInvalidDependencyResponse) {
			s.metrics.observeMinIO("error", minioStarted)
			if s.metrics != nil {
				s.metrics.providerResponseInvalid.Inc()
			}
			return Result{}, storageError(CodeInternalFailure, "provider_invalid")
		}
		s.metrics.observeMinIO("error", minioStarted)
		return Result{}, storageError(CodeServiceUnavailable, "provider_unavailable")
	}
	if !validIssuedCredentials(credentials, s.now(), request.DurationSeconds) {
		s.metrics.observeMinIO("error", minioStarted)
		if s.metrics != nil {
			s.metrics.providerResponseInvalid.Inc()
		}
		return Result{}, storageError(CodeInternalFailure, "provider_invalid")
	}
	s.metrics.observeMinIO("success", minioStarted)
	roleName := boundedAssumedRoleName(request.Role.BindingName, decision.Binding.UID)
	return Result{
		Credentials:    credentials,
		AssumedRoleARN: "arn:aws:sts::" + request.Role.AccountID + ":assumed-role/" + roleName + "/" + request.RoleSessionName,
		AssumedRoleID:  opaqueDigest(decision.Binding.UID) + ":" + request.RoleSessionName,
		Audience:       "tikti-workload-exchange", Provider: identity.Issuer, Subject: identity.Subject,
	}, nil
}

func validVerifiedIdentity(identity domain.WorkloadSubject) bool {
	parsed, valid := domain.ParseWorkloadSubject(identity.Subject)
	return valid && parsed.Namespace == identity.Namespace && parsed.ServiceAccount == identity.ServiceAccount &&
		validWorkloadIssuer(identity.Issuer) && validDNSLabel(identity.ClusterRef)
}

func validWorkloadIssuer(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == ""
}

func validIssuedCredentials(credentials Credentials, now time.Time, duration int) bool {
	return validCredential(credentials.AccessKeyID, 16, 128) && validCredential(credentials.SecretAccessKey, 16, 256) &&
		validCredential(credentials.SessionToken, 16, 16<<10) && credentials.Expiration.After(now.UTC()) &&
		!credentials.Expiration.After(now.UTC().Add(time.Duration(duration)*time.Second+5*time.Second))
}

func boundedAssumedRoleName(bindingName, bindingUID string) string {
	value := "codefoundry-" + bindingName
	if len(value) <= 64 {
		return value
	}
	return value[:47] + "-" + opaqueDigest(bindingUID)[:16]
}

func opaqueDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}

func storageError(code Code, reason string) *Error {
	return &Error{Code: code, HTTPStatus: statusForCode(code), Reason: closedReason(reason), Message: messageForCode(code)}
}

func statusForCode(code Code) int {
	switch code {
	case CodeInvalidParameterValue, CodeInvalidIdentityToken:
		return 400
	case CodeAccessDenied:
		return 403
	case CodeThrottling:
		return 429
	case CodeIDPCommunicationError, CodeServiceUnavailable:
		return 503
	default:
		return 500
	}
}

func messageForCode(code Code) string {
	switch code {
	case CodeInvalidParameterValue:
		return "The request parameters are invalid."
	case CodeInvalidIdentityToken:
		return "The web identity token is invalid."
	case CodeAccessDenied:
		return "Access is denied."
	case CodeThrottling:
		return "The request rate is too high."
	case CodeIDPCommunicationError, CodeServiceUnavailable:
		return "A required identity service is unavailable."
	default:
		return "The request could not be completed."
	}
}
