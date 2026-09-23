package services

import (
	"context"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// TrinoIdentityAuthority authorizes issuance, not catalog access. Implementations
// MUST verify an active installation registration, current tenant lifetime,
// current principal identity, and explicit query-scope entitlement on EVERY call.
// Workload resolution MUST bind the verified issuer/cluster/namespace/account to
// the current Service UID. Neither a legacy CodeQ grant nor a subject name alone
// establishes this authority. CFP-111 supplies durable registration and wiring;
// production constructors leave this nil until then (default OFF).
type TrinoIdentityAuthority interface {
	AuthorizeUser(context.Context, string, string, string) (domain.TrinoPrincipal, error)
	AuthorizeWorkload(context.Context, string, string, domain.WorkloadSubject) (domain.TrinoPrincipal, error)
}

func WithTrinoIdentityAuthority(authority TrinoIdentityAuthority) UserServiceOption {
	return func(s *userService) { s.trinoAuthority = authority }
}

type WorkloadIdentityServiceOption func(*workloadIdentityService)

func WithWorkloadTrinoIdentityAuthority(authority TrinoIdentityAuthority) WorkloadIdentityServiceOption {
	return func(s *workloadIdentityService) { s.trinoAuthority = authority }
}

// Reserve even malformed/whitespace-prefixed variants so they cannot fall back
// to the permissive legacy custom-audience path.
func reservedTrinoAudience(audience string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(audience)), "trino:")
}
func trinoRequest(audience, tenant string, scopes []string) (string, bool) {
	installation, valid := domain.TrinoInstallationAudience(audience)
	return installation, valid && tenantIDPattern.MatchString(tenant) && len(scopes) == 1 && scopes[0] == domain.TrinoQueryScope
}
func trinoClaims(p domain.TrinoPrincipal, installation, tenant, kind, subject, issuer string, now time.Time, ttl int) (jwt.MapClaims, error) {
	if p.InstallationUID != installation || p.TenantID != tenant || p.SubjectKind != kind || (kind == "User" && p.SubjectUID != subject) || issuer == "" {
		return nil, domain.ErrUnauthorizedScope
	}
	opaque, err := p.OpaquePrincipal()
	if err != nil {
		return nil, domain.ErrUnauthorizedScope
	}
	return jwt.MapClaims{"iss": issuer, "aud": "trino:" + installation, "sub": subject, "tid": tenant, "scope": domain.TrinoQueryScope, "trino_principal": opaque, "iat": now.Unix(), "exp": now.Unix() + int64(ttl), "jti": uuid.NewString()}, nil
}

func (s *userService) exchangeTrinoUser(ctx context.Context, req domain.TokenExchangeReq, u *domain.User, source jwt.MapClaims) (*domain.TokenExchangeResp, error) {
	installation, valid := trinoRequest(req.Audience, req.TenantID, req.Scopes)
	if !valid || s.trinoAuthority == nil || len(req.EventTypes) > 0 || req.DiscoverTenantTargetsV1 || req.DiscoverTenantTargetsV2 || req.ScopeCeilingV1 != nil {
		return nil, domain.ErrUnauthorizedScope
	}
	p, err := s.trinoAuthority.AuthorizeUser(ctx, installation, req.TenantID, u.Id)
	if err != nil {
		return nil, domain.ErrUnauthorizedScope
	}
	now := time.Now().UTC()
	ttl := req.TTLSeconds
	if ttl <= 0 || ttl > 300 {
		ttl = 300
	}
	expiry, err := source.GetExpirationTime()
	if err != nil || expiry == nil {
		return nil, domain.ErrInvalidToken
	}
	remaining := int(expiry.Unix() - now.Unix())
	if remaining <= 0 {
		return nil, domain.ErrInvalidToken
	}
	if remaining < ttl {
		ttl = remaining
	}
	claims, err := trinoClaims(p, installation, req.TenantID, "User", u.Id, s.issuerBaseURL, now, ttl)
	if err != nil {
		return nil, err
	}
	amr, valid := canonicalAuthenticationMethods(source)
	if !valid {
		return nil, domain.ErrInvalidToken
	}
	if len(amr) > 0 {
		claims["amr"] = amr
	}
	key, err := s.getRSAPrivateKey()
	if err != nil {
		return nil, domain.ErrAuthenticationUnavailable
	}
	if s.jwksKeyID == "" {
		return nil, domain.ErrAuthenticationUnavailable
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.jwksKeyID
	signed, err := token.SignedString(key)
	if err != nil {
		return nil, domain.ErrAuthenticationUnavailable
	}
	return &domain.TokenExchangeResp{AccessToken: signed, TokenType: "Bearer", ExpiresIn: ttl, Scopes: []string{domain.TrinoQueryScope}}, nil
}

func (s *workloadIdentityService) exchangeTrinoWorkload(ctx context.Context, req domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
	installation, valid := trinoRequest(req.Audience, req.TenantID, req.Scopes)
	if !valid || s.trinoAuthority == nil {
		return nil, domain.ErrWorkloadBindingDenied
	}
	subject, err := s.VerifyProjectedToken(ctx, req.SubjectToken)
	if err != nil {
		return nil, err
	}
	canonical, valid := domain.ParseWorkloadSubject(subject.Subject)
	if !valid || canonical.Subject != subject.Subject || canonical.Namespace != subject.Namespace || canonical.ServiceAccount != subject.ServiceAccount || subject.Issuer == "" || subject.ClusterRef == "" {
		return nil, domain.ErrWorkloadTokenInvalid
	}
	// VerifyProjectedToken supplies attested context; authority must match all of
	// it to the current Service incarnation rather than reuse a name-only binding.
	p, err := s.trinoAuthority.AuthorizeWorkload(ctx, installation, req.TenantID, subject)
	if err != nil {
		return nil, domain.ErrWorkloadBindingDenied
	}
	ttl := int(s.ttl / time.Second)
	if ttl <= 0 || ttl > 300 {
		ttl = 300
	}
	claims, err := trinoClaims(p, installation, req.TenantID, "Service", subject.Subject, s.issuer, s.now().UTC(), ttl)
	if err != nil {
		return nil, domain.ErrWorkloadBindingDenied
	}
	key, err := s.signingKey()
	if err != nil || s.keyID == "" {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID
	signed, err := token.SignedString(key)
	if err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	return &domain.WorkloadTokenExchangeResp{AccessToken: signed, TokenType: "Bearer", ExpiresIn: ttl, Audience: req.Audience, TenantID: req.TenantID, Scopes: []string{domain.TrinoQueryScope}}, nil
}
