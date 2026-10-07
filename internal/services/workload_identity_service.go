package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"log"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const defaultWorkloadAccessTokenTTL = 5 * time.Minute

var (
	tenantIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
)

type WorkloadTokenVerifier interface {
	Verify(ctx context.Context, subjectToken string) (domain.WorkloadSubject, error)
}

type WorkloadIdentityService interface {
	VerifyProjectedToken(ctx context.Context, subjectToken string) (domain.WorkloadSubject, error)
	Exchange(ctx context.Context, req domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error)
	UpsertBinding(ctx context.Context, req domain.WorkloadBindingUpsertReq) (*domain.WorkloadBinding, error)
	RevokeBinding(ctx context.Context, req domain.WorkloadBindingRevokeReq) (*domain.WorkloadBinding, error)
}

func (s *workloadIdentityService) VerifyProjectedToken(ctx context.Context, subjectToken string) (domain.WorkloadSubject, error) {
	if s.verifier == nil {
		return domain.WorkloadSubject{}, domain.ErrWorkloadIdentityUnavailable
	}
	subject, err := s.verifier.Verify(ctx, subjectToken)
	if err == nil {
		return subject, nil
	}
	if errors.Is(err, domain.ErrWorkloadTokenInvalid) {
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	log.Printf("workload identity verifier unavailable: %v", err)
	return domain.WorkloadSubject{}, domain.ErrWorkloadIdentityUnavailable
}

type workloadIdentityService struct {
	trinoAuthority  TrinoIdentityAuthority
	topicController CodeQTopicControllerIdentity
	topicTenants    CodeQTopicTenantReader
	repo            repository.WorkloadBindingRepository
	verifier        WorkloadTokenVerifier
	issuer          string
	privatePEM      string
	keyID           string
	ttl             time.Duration
	now             func() time.Time

	// trustedClusterRefs is the operator-configured clusterRef set; it bounds
	// which clusterRef a scoped WorkloadBinding may carry.
	trustedClusterRefs []string
	// scopedWorkloadBindings (ADR-0022 R4 flag, default false): when more than
	// one provider is trusted, upserts must carry clusterRef and unscoped
	// records are no longer authority.
	scopedWorkloadBindings bool
	// refuseLegacyCodeQAdmin is the inverse of workloadIdentity.legacyCodeQAdminGrant
	// (default true), so the zero value preserves today's behaviour.
	refuseLegacyCodeQAdmin bool
	metrics                *WorkloadIdentityMetrics

	keyOnce sync.Once
	key     *rsa.PrivateKey
	keyErr  error
}

func NewWorkloadIdentityService(
	repo repository.WorkloadBindingRepository,
	verifier WorkloadTokenVerifier,
	issuer string,
	privatePEM string,
	keyID string,
	ttl time.Duration,
	options ...WorkloadIdentityServiceOption,
) WorkloadIdentityService {
	if ttl <= 0 {
		ttl = defaultWorkloadAccessTokenTTL
	}
	if ttl > time.Hour {
		ttl = time.Hour
	}
	service := &workloadIdentityService{
		repo: repo, verifier: verifier, issuer: strings.TrimSpace(issuer), privatePEM: privatePEM,
		keyID: strings.TrimSpace(keyID), ttl: ttl, now: time.Now,
	}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *workloadIdentityService) Exchange(ctx context.Context, req domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
	if strings.TrimSpace(req.SubjectToken) == "" || req.SubjectTokenType != domain.WorkloadSubjectTokenType {
		return nil, domain.ErrWorkloadTokenInvalid
	}
	if slices.Contains(normalizedWorkloadScopes(req.Scopes), CodeQTopicManageScope) {
		return s.exchangeCodeQTopic(ctx, req)
	}
	if reservedTrinoAudience(req.Audience) {
		return s.exchangeTrinoWorkload(ctx, req)
	}
	if !workloadAudienceAllowed(req.Audience) || !tenantIDPattern.MatchString(req.TenantID) {
		return nil, domain.ErrInvalidArgument
	}
	if !workloadScopesAllowed(req.Audience, req.Scopes) {
		return nil, domain.ErrWorkloadBindingDenied
	}
	if s.verifier == nil || s.repo == nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}

	subject, err := s.VerifyProjectedToken(ctx, req.SubjectToken)
	if err != nil {
		if errors.Is(err, domain.ErrWorkloadTokenInvalid) {
			return nil, domain.ErrWorkloadTokenInvalid
		}
		log.Printf("workload identity verifier unavailable: %v", err)
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	if req.Audience == domain.WorkloadProducerAudience {
		// The only producer scope set on this path is exactly {codeq:admin}.
		s.metrics.legacyCodeQAdminExchange(subject.ClusterRef, subject.Namespace)
		if s.refuseLegacyCodeQAdmin {
			return nil, domain.ErrWorkloadBindingDenied
		}
	}
	binding, err := s.legacyBinding(ctx, subject)
	if err != nil {
		log.Printf("workload identity binding lookup unavailable: %v", err)
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	grant, allowed := workloadBindingGrant(binding, subject, req.TenantID, req.Audience, req.Scopes)
	if !allowed {
		return nil, domain.ErrWorkloadBindingDenied
	}

	if s.issuer == "" || s.keyID == "" {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	key, err := s.signingKey()
	if err != nil {
		log.Printf("workload identity signing unavailable: %v", err)
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	now := s.now().UTC()
	claims := jwt.MapClaims{
		"iss":   s.issuer,
		"aud":   req.Audience,
		"sub":   subject.Subject,
		"tid":   req.TenantID,
		"scope": strings.Join(normalizedWorkloadScopes(req.Scopes), " "),
		"iat":   now.Unix(),
		"exp":   now.Add(s.ttl).Unix(),
		"jti":   uuid.NewString(),
	}
	if len(grant.EventTypes) > 0 {
		claims["eventTypes"] = grant.EventTypes
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.keyID != "" {
		token.Header["kid"] = s.keyID
	}
	signed, err := token.SignedString(key)
	if err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	return &domain.WorkloadTokenExchangeResp{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.ttl / time.Second),
		Audience:    req.Audience,
		Scopes:      normalizedWorkloadScopes(req.Scopes),
		TenantID:    req.TenantID,
		EventTypes:  slices.Clone(grant.EventTypes),
	}, nil
}

func (s *workloadIdentityService) UpsertBinding(ctx context.Context, req domain.WorkloadBindingUpsertReq) (*domain.WorkloadBinding, error) {
	if s.repo == nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	subject, valid := domain.ParseWorkloadSubject(req.Subject)
	if !valid || subject.Namespace != strings.TrimSpace(req.Namespace) || subject.ServiceAccount != strings.TrimSpace(req.ServiceAccount) || len(req.Grants) == 0 || len(req.Grants) > domain.MaxWorkloadGrants {
		return nil, domain.ErrInvalidArgument
	}
	clusterRef, serviceAccountUID := req.ClusterRef, req.ServiceAccountUID
	if clusterRef != "" && !slices.Contains(s.trustedClusterRefs, clusterRef) {
		return nil, domain.ErrInvalidArgument
	}
	if serviceAccountUID != "" && !domain.ValidWorkloadObjectUID(serviceAccountUID) {
		return nil, domain.ErrInvalidArgument
	}
	if clusterRef == "" && s.scopedBindingsRequired() {
		return nil, domain.ErrInvalidArgument
	}
	grants := make([]domain.WorkloadGrant, 0, len(req.Grants))
	seen := make(map[string]struct{}, len(req.Grants))
	for _, grant := range req.Grants {
		if !tenantIDPattern.MatchString(grant.TenantID) ||
			!workloadAudienceAllowed(grant.Audience) ||
			!workloadScopesAllowed(grant.Audience, grant.Scopes) ||
			!workloadEventTypesAllowed(grant.Audience, grant.EventTypes) {
			return nil, domain.ErrInvalidArgument
		}
		grantKey := grant.TenantID + "\x00" + grant.Audience
		if _, duplicate := seen[grantKey]; duplicate {
			return nil, domain.ErrInvalidArgument
		}
		seen[grantKey] = struct{}{}
		grants = append(grants, domain.WorkloadGrant{
			TenantID: grant.TenantID, Audience: grant.Audience,
			Scopes:     normalizedWorkloadScopes(grant.Scopes),
			EventTypes: normalizedWorkloadEventTypes(grant.EventTypes),
		})
	}
	binding := &domain.WorkloadBinding{
		Subject: subject.Subject, Namespace: subject.Namespace,
		ServiceAccount: subject.ServiceAccount, ClusterRef: clusterRef, ServiceAccountUID: serviceAccountUID,
		Grants: grants, UpdatedAt: s.now().UTC(),
	}
	if err := s.repo.Upsert(ctx, binding); err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	return binding, nil
}

func (s *workloadIdentityService) RevokeBinding(ctx context.Context, req domain.WorkloadBindingRevokeReq) (*domain.WorkloadBinding, error) {
	subject, valid := domain.ParseWorkloadSubject(req.Subject)
	if s.repo == nil || !valid || (req.ClusterRef != "" && !domain.ValidWorkloadClusterRef(req.ClusterRef)) {
		return nil, domain.ErrInvalidArgument
	}
	binding, err := s.repo.Revoke(ctx, domain.WorkloadBindingKey(req.ClusterRef, subject.Subject), s.now().UTC())
	if err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	if binding == nil {
		return nil, domain.ErrNotFound
	}
	return binding, nil
}

func (s *workloadIdentityService) signingKey() (*rsa.PrivateKey, error) {
	s.keyOnce.Do(func() {
		key, err := utils.ParseRSAPrivateKey(s.privatePEM)
		if err != nil {
			s.keyErr = err
			return
		}
		if key.N.BitLen() < 2048 {
			s.keyErr = errors.New("workload signing key must be at least 2048 bits")
			return
		}
		s.key = key
	})
	return s.key, s.keyErr
}

func workloadAudienceAllowed(audience string) bool {
	return audience == domain.WorkloadProducerAudience || audience == domain.WorkloadWorkerAudience
}

func normalizedWorkloadScopes(scopes []string) []string {
	normalized := normalizeList(scopes)
	slices.Sort(normalized)
	return slices.Compact(normalized)
}

func workloadScopesAllowed(audience string, scopes []string) bool {
	normalized := normalizedWorkloadScopes(scopes)
	switch audience {
	case domain.WorkloadProducerAudience:
		return slices.Equal(normalized, []string{domain.WorkloadAdminScope})
	case domain.WorkloadWorkerAudience:
		return slices.Equal(normalized, []string{
			domain.WorkloadClaimScope,
			domain.WorkloadNackScope,
			domain.WorkloadResultScope,
		})
	default:
		return false
	}
}

func normalizedWorkloadEventTypes(eventTypes []string) []string {
	normalized := normalizeList(eventTypes)
	slices.Sort(normalized)
	return slices.Compact(normalized)
}

func workloadEventTypesAllowed(audience string, eventTypes []string) bool {
	normalized := normalizedWorkloadEventTypes(eventTypes)
	if audience == domain.WorkloadProducerAudience {
		return len(normalized) == 0
	}
	if audience != domain.WorkloadWorkerAudience || len(normalized) == 0 || len(normalized) > domain.MaxWorkloadEventTypes {
		return false
	}
	for _, eventType := range normalized {
		if len(eventType) > 128 || strings.ContainsAny(eventType, "\r\n\t") {
			return false
		}
	}
	return true
}

// scopedBindingsRequired reports whether unscoped WorkloadBinding records are
// refused: the R4 flag is on and more than one provider is trusted.
func (s *workloadIdentityService) scopedBindingsRequired() bool {
	return s.scopedWorkloadBindings && len(s.trustedClusterRefs) > 1
}

// legacyBinding resolves the WorkloadBinding for a verified subject. A record
// scoped to the verified clusterRef wins. An unscoped legacy record is read
// only when no scoped record exists and scoped records are not required.
func (s *workloadIdentityService) legacyBinding(ctx context.Context, subject domain.WorkloadSubject) (*domain.WorkloadBinding, error) {
	if subject.ClusterRef != "" {
		scoped, err := s.repo.Get(ctx, domain.WorkloadBindingKey(subject.ClusterRef, subject.Subject))
		if err != nil || scoped != nil {
			return scoped, err
		}
	}
	if s.scopedBindingsRequired() {
		return nil, nil
	}
	binding, err := s.repo.Get(ctx, subject.Subject)
	if err == nil && binding != nil && binding.ClusterRef == "" {
		s.metrics.legacyUnscopedBinding()
	}
	return binding, err
}

func workloadBindingGrant(binding *domain.WorkloadBinding, subject domain.WorkloadSubject, tenantID, audience string, scopes []string) (domain.WorkloadGrant, bool) {
	if binding == nil || binding.Revoked || binding.Subject != subject.Subject || binding.Namespace != subject.Namespace || binding.ServiceAccount != subject.ServiceAccount {
		return domain.WorkloadGrant{}, false
	}
	// Optional scoping fields are always matched against the verified subject.
	if (binding.ClusterRef != "" && binding.ClusterRef != subject.ClusterRef) ||
		(binding.ServiceAccountUID != "" && binding.ServiceAccountUID != subject.ServiceAccountUID) {
		return domain.WorkloadGrant{}, false
	}
	for _, grant := range binding.Grants {
		if grant.TenantID == tenantID && grant.Audience == audience &&
			slices.Equal(normalizedWorkloadScopes(grant.Scopes), normalizedWorkloadScopes(scopes)) &&
			workloadEventTypesAllowed(grant.Audience, grant.EventTypes) {
			grant.Scopes = normalizedWorkloadScopes(grant.Scopes)
			grant.EventTypes = normalizedWorkloadEventTypes(grant.EventTypes)
			return grant, true
		}
	}
	return domain.WorkloadGrant{}, false
}
