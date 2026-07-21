package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"regexp"
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
	Exchange(ctx context.Context, req domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error)
	UpsertBinding(ctx context.Context, req domain.WorkloadBindingUpsertReq) (*domain.WorkloadBinding, error)
	RevokeBinding(ctx context.Context, req domain.WorkloadBindingRevokeReq) (*domain.WorkloadBinding, error)
}

type workloadIdentityService struct {
	repo       repository.WorkloadBindingRepository
	verifier   WorkloadTokenVerifier
	issuer     string
	privatePEM string
	keyID      string
	ttl        time.Duration
	now        func() time.Time

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
) WorkloadIdentityService {
	if ttl <= 0 {
		ttl = defaultWorkloadAccessTokenTTL
	}
	if ttl > time.Hour {
		ttl = time.Hour
	}
	return &workloadIdentityService{
		repo: repo, verifier: verifier, issuer: strings.TrimSpace(issuer), privatePEM: privatePEM,
		keyID: strings.TrimSpace(keyID), ttl: ttl, now: time.Now,
	}
}

func (s *workloadIdentityService) Exchange(ctx context.Context, req domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
	if strings.TrimSpace(req.SubjectToken) == "" || req.SubjectTokenType != domain.WorkloadSubjectTokenType {
		return nil, domain.ErrWorkloadTokenInvalid
	}
	if req.Audience != domain.WorkloadTargetAudience || !tenantIDPattern.MatchString(req.TenantID) {
		return nil, domain.ErrInvalidArgument
	}
	if !exactWorkloadScopes(req.Scopes) {
		return nil, domain.ErrWorkloadBindingDenied
	}
	if s.verifier == nil || s.repo == nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}

	subject, err := s.verifier.Verify(ctx, req.SubjectToken)
	if err != nil {
		if errors.Is(err, domain.ErrWorkloadTokenInvalid) {
			return nil, domain.ErrWorkloadTokenInvalid
		}
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	binding, err := s.repo.Get(ctx, subject.Subject)
	if err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	if !bindingAllows(binding, subject, req.TenantID, req.Audience, req.Scopes) {
		return nil, domain.ErrWorkloadBindingDenied
	}

	if s.issuer == "" || s.keyID == "" {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	key, err := s.signingKey()
	if err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	now := s.now().UTC()
	claims := jwt.MapClaims{
		"iss":   s.issuer,
		"aud":   req.Audience,
		"sub":   subject.Subject,
		"tid":   req.TenantID,
		"scope": domain.WorkloadAdminScope,
		"iat":   now.Unix(),
		"exp":   now.Add(s.ttl).Unix(),
		"jti":   uuid.NewString(),
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
		Scopes:      []string{domain.WorkloadAdminScope},
		TenantID:    req.TenantID,
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
	grants := make([]domain.WorkloadGrant, 0, len(req.Grants))
	seen := make(map[string]struct{}, len(req.Grants))
	for _, grant := range req.Grants {
		if !tenantIDPattern.MatchString(grant.TenantID) || grant.Audience != domain.WorkloadTargetAudience || !exactWorkloadScopes(grant.Scopes) {
			return nil, domain.ErrInvalidArgument
		}
		if _, duplicate := seen[grant.TenantID]; duplicate {
			return nil, domain.ErrInvalidArgument
		}
		seen[grant.TenantID] = struct{}{}
		grants = append(grants, domain.WorkloadGrant{
			TenantID: grant.TenantID, Audience: grant.Audience, Scopes: []string{domain.WorkloadAdminScope},
		})
	}
	binding := &domain.WorkloadBinding{
		Subject: subject.Subject, Namespace: subject.Namespace,
		ServiceAccount: subject.ServiceAccount, Grants: grants, UpdatedAt: s.now().UTC(),
	}
	if err := s.repo.Upsert(ctx, binding); err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	return binding, nil
}

func (s *workloadIdentityService) RevokeBinding(ctx context.Context, req domain.WorkloadBindingRevokeReq) (*domain.WorkloadBinding, error) {
	subject, valid := domain.ParseWorkloadSubject(req.Subject)
	if s.repo == nil || !valid {
		return nil, domain.ErrInvalidArgument
	}
	binding, err := s.repo.Revoke(ctx, subject.Subject, s.now().UTC())
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

func exactWorkloadScopes(scopes []string) bool {
	return len(scopes) == 1 && scopes[0] == domain.WorkloadAdminScope
}

func bindingAllows(binding *domain.WorkloadBinding, subject domain.WorkloadSubject, tenantID, audience string, scopes []string) bool {
	if binding == nil || binding.Revoked || binding.Subject != subject.Subject || binding.Namespace != subject.Namespace || binding.ServiceAccount != subject.ServiceAccount {
		return false
	}
	for _, grant := range binding.Grants {
		if grant.TenantID == tenantID && grant.Audience == audience && exactWorkloadScopes(grant.Scopes) && exactWorkloadScopes(scopes) {
			return true
		}
	}
	return false
}
