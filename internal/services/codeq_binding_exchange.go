package services

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/internal/codeqbinding"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// Stable ADR-0022 C3 refusal codes. Authority denials are "Authority" + the
// closed C2 reason (for example AuthorityPlacementMismatch).
const (
	CodeQBindingCodeIssued               = "Issued"
	CodeQBindingCodeFeatureDisabled      = "FeatureDisabled"
	CodeQBindingCodeInvalidRequest       = "InvalidRequest"
	CodeQBindingCodeSubjectTokenInvalid  = "SubjectTokenInvalid"
	CodeQBindingCodeUnboundSubjectToken  = "UnboundSubjectToken"
	CodeQBindingCodeIssuerAmbiguous      = "IssuerAmbiguous"
	CodeQBindingCodeTenantInactive       = "TenantInactive"
	CodeQBindingCodeRateLimited          = "RateLimited"
	CodeQBindingCodeAuthorityBusy        = "AuthorityBusy"
	CodeQBindingCodeAuthorityUnavailable = "AuthorityUnavailable"
	CodeQBindingCodeBindingNotFound      = "BindingNotFound"
	CodeQBindingCodeBindingAmbiguous     = "BindingAmbiguous"
	CodeQBindingCodeSubjectTokenExpiring = "SubjectTokenExpiring"
	// CodeQBindingCodeIdentityUnavailable covers a local dependency outage
	// (projected-token JWKS, tenant store or signing key). It is not listed in
	// ADR-0022 C3 and is reported as an ADR gap.
	CodeQBindingCodeIdentityUnavailable = "IdentityUnavailable"

	codeqPublishScope        = "codeq:publish"
	codeqAbandonScope        = "codeq:abandon"
	codeqHeartbeatScope      = "codeq:heartbeat"
	codeqBindingClaim        = "codeq_binding"
	codeqBindingMinimumTTL   = 30 * time.Second
	codeqBindingMaximumTTL   = 300 * time.Second
	codeqBindingAssertionTTL = 60 * time.Second
	codeqBindingRateWindow   = time.Minute
)

var (
	codeqPublishScopes   = []string{codeqPublishScope}
	codeqSubscribeScopes = []string{codeqAbandonScope, domain.WorkloadClaimScope, codeqHeartbeatScope, domain.WorkloadNackScope, domain.WorkloadResultScope}
)

// CodeQBindingExchangeConfig is the trusted, validated C3 configuration.
type CodeQBindingExchangeConfig struct {
	Enabled              bool
	AccessTokenTTL       time.Duration
	MaximumConcurrent    int
	PerIdentityPerMinute int
}

type codeqBindingExchange struct {
	enabled   bool
	ttl       time.Duration
	authority codeqbinding.Authority
	tenants   CodeQTopicTenantReader
	limiter   *codeqbinding.IdentityRateLimiter
	inflight  chan struct{}
	auditf    func(string, ...any)
}

// WithCodeQBindingExchange installs the ADR-0022 C3 grant. Disabled (or
// absent) answers every codeqTopicId request with 403 FeatureDisabled.
func WithCodeQBindingExchange(cfg CodeQBindingExchangeConfig, authority codeqbinding.Authority, tenants CodeQTopicTenantReader) WorkloadIdentityServiceOption {
	return func(s *workloadIdentityService) {
		exchange := &codeqBindingExchange{
			enabled: cfg.Enabled, ttl: cfg.AccessTokenTTL, authority: authority, tenants: tenants,
			auditf: log.Printf,
		}
		if cfg.MaximumConcurrent > 0 {
			exchange.inflight = make(chan struct{}, cfg.MaximumConcurrent)
		}
		if cfg.PerIdentityPerMinute > 0 {
			exchange.limiter = codeqbinding.NewIdentityRateLimiter(cfg.PerIdentityPerMinute, codeqBindingRateWindow)
		}
		s.codeqBindings = exchange
	}
}

// codeqBindingDecision is the redacted per-exchange audit record. It never
// holds a subject token, access token, assertion or any hash of them.
type codeqBindingDecision struct {
	correlationID     string
	code              string
	tenantID          string
	clusterRef        string
	namespace         string
	serviceAccount    string
	serviceAccountUID string
	podUID            string
	topicID           string
	policy            string
	bindingUID        string
	bindingGeneration int64
	authorityLatency  time.Duration
	jti               string
	exp               int64
}

func (s *workloadIdentityService) exchangeCodeQBinding(ctx context.Context, req domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
	decision := &codeqBindingDecision{
		correlationID: uuid.NewString(), tenantID: req.TenantID, topicID: req.CodeQTopicID,
	}
	response, refusal := s.codeqBindingProcedure(ctx, req, decision)
	s.recordCodeQBindingDecision(decision, refusal)
	if refusal != nil {
		return nil, refusal
	}
	return response, nil
}

func refuse(decision *codeqBindingDecision, status int, code string, retryAfter int) *domain.WorkloadExchangeError {
	decision.code = code
	return &domain.WorkloadExchangeError{Status: status, Code: code, CorrelationID: decision.correlationID, RetryAfterSeconds: retryAfter}
}

// codeqBindingProcedure implements ADR-0022 C3 steps 1-9 in order; the first
// failure decides. Nothing is stored or cached.
func (s *workloadIdentityService) codeqBindingProcedure(ctx context.Context, req domain.WorkloadTokenExchangeReq, decision *codeqBindingDecision) (*domain.WorkloadTokenExchangeResp, *domain.WorkloadExchangeError) {
	// Dispatch: this grant never combines with the topic-manage or Trino grants.
	if slices.Contains(normalizedWorkloadScopes(req.Scopes), CodeQTopicManageScope) || reservedTrinoAudience(req.Audience) {
		return nil, refuse(decision, http.StatusBadRequest, CodeQBindingCodeInvalidRequest, 0)
	}
	exchange := s.codeqBindings
	// Step 1: feature flag.
	if exchange == nil || !exchange.enabled {
		return nil, refuse(decision, http.StatusForbidden, CodeQBindingCodeFeatureDisabled, 0)
	}
	// Step 2: request shape. Policy comes only from audience + exact scope set.
	policy, scopes, valid := codeqBindingPolicy(req.Audience, req.Scopes)
	topicName, topicValid := codeqBindingTopicName(req.TenantID, req.CodeQTopicID)
	if !valid || !topicValid || req.SubjectTokenType != domain.WorkloadSubjectTokenType {
		return nil, refuse(decision, http.StatusBadRequest, CodeQBindingCodeInvalidRequest, 0)
	}
	decision.policy = policy
	if exchange.authority == nil || exchange.tenants == nil || exchange.limiter == nil || exchange.inflight == nil ||
		exchange.ttl < codeqBindingMinimumTTL || exchange.ttl > codeqBindingMaximumTTL {
		return nil, refuse(decision, http.StatusServiceUnavailable, CodeQBindingCodeAuthorityUnavailable, 0)
	}
	// Step 3: verified, bound subject token; clusterRef only from the trusted issuer map.
	if strings.TrimSpace(req.SubjectToken) == "" {
		return nil, refuse(decision, http.StatusUnauthorized, CodeQBindingCodeSubjectTokenInvalid, 0)
	}
	subject, err := s.VerifyProjectedToken(ctx, req.SubjectToken)
	if err != nil {
		if errors.Is(err, domain.ErrWorkloadTokenInvalid) {
			return nil, refuse(decision, http.StatusUnauthorized, CodeQBindingCodeSubjectTokenInvalid, 0)
		}
		return nil, refuse(decision, http.StatusServiceUnavailable, CodeQBindingCodeIdentityUnavailable, 0)
	}
	canonical, canonicalOK := domain.ParseWorkloadSubject(subject.Subject)
	if !canonicalOK || canonical.Subject != subject.Subject || canonical.Namespace != subject.Namespace ||
		canonical.ServiceAccount != subject.ServiceAccount || subject.ExpiresAt.IsZero() {
		return nil, refuse(decision, http.StatusUnauthorized, CodeQBindingCodeSubjectTokenInvalid, 0)
	}
	decision.namespace, decision.serviceAccount = subject.Namespace, subject.ServiceAccount
	decision.serviceAccountUID, decision.podUID = subject.ServiceAccountUID, subject.PodUID
	if subject.ServiceAccountUID == "" || subject.PodUID == "" {
		return nil, refuse(decision, http.StatusUnauthorized, CodeQBindingCodeUnboundSubjectToken, 0)
	}
	if !codeqbinding.ValidCanonicalUUID(subject.ServiceAccountUID) || !codeqbinding.ValidCanonicalUUID(subject.PodUID) {
		return nil, refuse(decision, http.StatusUnauthorized, CodeQBindingCodeSubjectTokenInvalid, 0)
	}
	if subject.ClusterRef == "" || !domain.ValidWorkloadClusterRef(subject.ClusterRef) {
		return nil, refuse(decision, http.StatusForbidden, CodeQBindingCodeIssuerAmbiguous, 0)
	}
	decision.clusterRef = subject.ClusterRef
	// Step 4: tenant Active, read directly from the tenant store with the
	// predicate shared with topicAuthority (never topicAuthority itself).
	now := s.now().UTC()
	tenant, err := exchange.tenants.GetRetained(ctx, req.TenantID, now)
	if err != nil {
		return nil, refuse(decision, http.StatusServiceUnavailable, CodeQBindingCodeIdentityUnavailable, 0)
	}
	if !activeTenant(tenant, req.TenantID, now) {
		return nil, refuse(decision, http.StatusForbidden, CodeQBindingCodeTenantInactive, 0)
	}
	// Step 5: per-Pod-identity rate limit, then bounded authority concurrency.
	if allowed, retryAfter := exchange.limiter.Allow(codeqbinding.IdentityKey(subject.ClusterRef, subject.Namespace, subject.ServiceAccount, subject.PodUID)); !allowed {
		return nil, refuse(decision, http.StatusTooManyRequests, CodeQBindingCodeRateLimited, retryAfter)
	}
	select {
	case exchange.inflight <- struct{}{}:
	default:
		return nil, refuse(decision, http.StatusServiceUnavailable, CodeQBindingCodeAuthorityBusy, 1)
	}
	// Step 6: exact-audience service assertion, one call, no cache, no retry.
	authorityRequest := codeqbinding.AuthorityRequest{
		SchemaVersion: codeqbinding.SchemaVersion, RequestID: decision.correlationID, TenantID: req.TenantID,
		ClusterRef: subject.ClusterRef, Namespace: subject.Namespace, ServiceAccountName: subject.ServiceAccount,
		ServiceAccountUID: subject.ServiceAccountUID, PodUID: subject.PodUID,
	}
	authorityDecision, authorityErr := func() (codeqbinding.AuthorityDecision, *domain.WorkloadExchangeError) {
		defer func() { <-exchange.inflight }()
		return s.callCodeQBindingAuthority(ctx, exchange, authorityRequest, decision)
	}()
	if authorityErr != nil {
		return nil, authorityErr
	}
	// Step 7: authority denial carries the closed C2 reason.
	if !authorityDecision.IsAllowed() {
		return nil, refuse(decision, http.StatusForbidden, "Authority"+authorityDecision.Reason, 0)
	}
	// Step 8: exactly one eligible binding for this topic and policy.
	var selected []codeqbinding.Binding
	for _, binding := range authorityDecision.Bindings {
		if binding.TopicID == req.CodeQTopicID && binding.Policy == policy {
			selected = append(selected, binding)
		}
	}
	switch len(selected) {
	case 0:
		return nil, refuse(decision, http.StatusForbidden, CodeQBindingCodeBindingNotFound, 0)
	case 1:
	default:
		return nil, refuse(decision, http.StatusForbidden, CodeQBindingCodeBindingAmbiguous, 0)
	}
	binding := selected[0]
	decision.bindingUID, decision.bindingGeneration = binding.BindingUID, binding.Generation
	// Step 9: ttl = min(configured, remaining subject lifetime) and >= 30 s.
	issuedAt := s.now().UTC().Truncate(time.Second)
	ttl := exchange.ttl
	if remaining := subject.ExpiresAt.Sub(issuedAt).Truncate(time.Second); remaining < ttl {
		ttl = remaining
	}
	if ttl < codeqBindingMinimumTTL {
		return nil, refuse(decision, http.StatusUnauthorized, CodeQBindingCodeSubjectTokenExpiring, 0)
	}
	signed, jti, exp, err := s.signCodeQBindingToken(subject, req.TenantID, req.Audience, scopes, topicName, binding, issuedAt, ttl)
	if err != nil {
		return nil, refuse(decision, http.StatusServiceUnavailable, CodeQBindingCodeIdentityUnavailable, 0)
	}
	decision.code, decision.jti, decision.exp = CodeQBindingCodeIssued, jti, exp
	return &domain.WorkloadTokenExchangeResp{
		AccessToken: signed, TokenType: "Bearer", ExpiresIn: int(ttl / time.Second), Audience: req.Audience,
		Scopes: slices.Clone(scopes), TenantID: req.TenantID, EventTypes: []string{topicName},
	}, nil
}

func (s *workloadIdentityService) callCodeQBindingAuthority(ctx context.Context, exchange *codeqBindingExchange, request codeqbinding.AuthorityRequest, decision *codeqBindingDecision) (codeqbinding.AuthorityDecision, *domain.WorkloadExchangeError) {
	s.metrics.codeqBindingAuthorityInFlight(1)
	defer s.metrics.codeqBindingAuthorityInFlight(-1)
	assertion, err := s.signCodeQBindingAssertion()
	if err != nil {
		return codeqbinding.AuthorityDecision{}, refuse(decision, http.StatusServiceUnavailable, CodeQBindingCodeIdentityUnavailable, 0)
	}
	started := time.Now()
	result, err := exchange.authority.Authorize(ctx, request, assertion)
	decision.authorityLatency = time.Since(started)
	switch {
	case err != nil:
		s.metrics.codeqBindingAuthority("unavailable", started)
		return codeqbinding.AuthorityDecision{}, refuse(decision, http.StatusServiceUnavailable, CodeQBindingCodeAuthorityUnavailable, 0)
	case !codeqbinding.ValidDecision(request, result):
		// Defence in depth for Authority implementations other than Client.
		s.metrics.codeqBindingAuthority("invalid", started)
		return codeqbinding.AuthorityDecision{}, refuse(decision, http.StatusServiceUnavailable, CodeQBindingCodeAuthorityUnavailable, 0)
	case result.IsAllowed():
		s.metrics.codeqBindingAuthority("allowed", started)
	default:
		s.metrics.codeqBindingAuthority("denied", started)
	}
	return result, nil
}

// signCodeQBindingAssertion signs the C2 caller assertion: exact audience and
// subject, jti, nbf = iat - 5 s, exp = iat + 60 s; no tid, scope or eventTypes.
func (s *workloadIdentityService) signCodeQBindingAssertion() (string, error) {
	if s.issuer == "" || s.keyID == "" {
		return "", domain.ErrWorkloadIdentityUnavailable
	}
	key, err := s.signingKey()
	if err != nil {
		return "", err
	}
	now := s.now().UTC().Truncate(time.Second)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": strings.TrimSuffix(s.issuer, "/"), "aud": codeqbinding.AuthorityAudience,
		"sub": codeqbinding.ServiceSubject, "jti": uuid.NewString(),
		"iat": now.Unix(), "nbf": now.Add(-5 * time.Second).Unix(), "exp": now.Add(codeqBindingAssertionTTL).Unix(),
	})
	token.Header["kid"] = s.keyID
	token.Header["typ"] = "JWT"
	return token.SignedString(key)
}

// signCodeQBindingToken mints exactly the ADR-0022 C1.1/C3 claim set.
func (s *workloadIdentityService) signCodeQBindingToken(subject domain.WorkloadSubject, tenantID, audience string, scopes []string, topicName string, binding codeqbinding.Binding, issuedAt time.Time, ttl time.Duration) (string, string, int64, error) {
	if s.issuer == "" || s.keyID == "" {
		return "", "", 0, domain.ErrWorkloadIdentityUnavailable
	}
	key, err := s.signingKey()
	if err != nil {
		return "", "", 0, err
	}
	jti := uuid.NewString()
	exp := issuedAt.Add(ttl).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":        s.issuer,
		"aud":        audience,
		"sub":        CodeQBindingSubject(subject.ClusterRef, subject.Namespace, subject.ServiceAccount, subject.PodUID),
		"tid":        tenantID,
		"scope":      strings.Join(scopes, " "),
		"eventTypes": []string{topicName},
		codeqBindingClaim: map[string]any{
			"uid": binding.BindingUID, "generation": binding.Generation,
			"policy": binding.Policy, "topicId": binding.TopicID,
		},
		"cluster_ref": subject.ClusterRef,
		"iat":         issuedAt.Unix(),
		"exp":         exp,
		"jti":         jti,
	})
	token.Header["kid"] = s.keyID
	signed, err := token.SignedString(key)
	return signed, jti, exp, err
}

// CodeQBindingSubject is the per-Pod, per-cluster CodeQ worker identity. It can
// never collide with codecloud-worker, a Kubernetes subject or another cluster.
func CodeQBindingSubject(clusterRef, namespace, serviceAccount, podUID string) string {
	return "codefoundry:workload:" + clusterRef + ":" + namespace + ":" + serviceAccount + ":" + podUID
}

// codeqBindingPolicy derives the policy from the audience and the exact scope
// set. Duplicates and whitespace variants are refused, not normalized.
func codeqBindingPolicy(audience string, scopes []string) (string, []string, bool) {
	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	switch audience {
	case domain.WorkloadProducerAudience:
		if slices.Equal(sorted, codeqPublishScopes) {
			return codeqbinding.PolicyPublish, slices.Clone(codeqPublishScopes), true
		}
	case domain.WorkloadWorkerAudience:
		if slices.Equal(sorted, codeqSubscribeScopes) {
			return codeqbinding.PolicySubscribe, slices.Clone(codeqSubscribeScopes), true
		}
	}
	return "", nil, false
}

// codeqBindingTopicName returns name when topicID == tenantID + "." + name and
// name is a DNS label of at most 63 characters.
func codeqBindingTopicName(tenantID, topicID string) (string, bool) {
	if !tenantIDPattern.MatchString(tenantID) {
		return "", false
	}
	name, found := strings.CutPrefix(topicID, tenantID+".")
	if !found || !codeqbinding.ValidTopicName(name) {
		return "", false
	}
	return name, true
}

func (s *workloadIdentityService) recordCodeQBindingDecision(decision *codeqBindingDecision, refusal *domain.WorkloadExchangeError) {
	result := "issued"
	if refusal != nil {
		result = "denied"
		if refusal.Status >= http.StatusInternalServerError {
			result = "error"
		}
	}
	s.metrics.codeqBindingExchange(result, decision.code, decision.policy, decision.clusterRef)
	auditf := log.Printf
	if s.codeqBindings != nil && s.codeqBindings.auditf != nil {
		auditf = s.codeqBindings.auditf
	}
	decisionLabel := "deny"
	if refusal == nil {
		decisionLabel = "allow"
	}
	line := "audit event=codeq_binding_exchange decision=%s code=%.64q correlationId=%.64q tenantId=%.64q clusterRef=%.64q namespace=%.64q serviceAccount=%.253q serviceAccountUid=%.64q podUid=%.64q topicId=%.130q policy=%.16q bindingUid=%.128q bindingGeneration=%d authorityLatencyMs=%d"
	args := []any{
		decisionLabel, decision.code, decision.correlationID, decision.tenantID, decision.clusterRef,
		decision.namespace, decision.serviceAccount, decision.serviceAccountUID, decision.podUID,
		decision.topicID, decision.policy, decision.bindingUID, decision.bindingGeneration,
		decision.authorityLatency.Milliseconds(),
	}
	if refusal == nil {
		line += " jti=%.64q exp=%d"
		args = append(args, decision.jti, decision.exp)
	}
	auditf(line, args...)
}
