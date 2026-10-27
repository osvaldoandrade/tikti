package services

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/internal/codeqbinding"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type AIUserTokenValidator interface {
	ValidateAIAccessToken(context.Context, string) (aigateway.Claims, error)
}

type aiGatewayExchange struct {
	cfg       config.AIGatewayConfig
	authority aigateway.Authority
	tenants   CodeQTopicTenantReader
	users     AIUserTokenValidator
	slots     chan struct{}
	limiter   *codeqbinding.IdentityRateLimiter
}

func newAIGatewayExchange(cfg config.AIGatewayConfig, authority aigateway.Authority, tenants CodeQTopicTenantReader) *aiGatewayExchange {
	e := &aiGatewayExchange{cfg: cfg, authority: authority, tenants: tenants}
	if cfg.MaximumConcurrent > 0 && cfg.MaximumConcurrent <= 32 {
		e.slots = make(chan struct{}, cfg.MaximumConcurrent)
	}
	if cfg.PerIdentityPerMinute > 0 && cfg.PerIdentityPerMinute <= 60 {
		e.limiter = codeqbinding.NewIdentityRateLimiter(cfg.PerIdentityPerMinute, time.Minute)
	}
	return e
}

func WithAIGateway(cfg config.AIGatewayConfig, authority aigateway.Authority, tenants CodeQTopicTenantReader) UserServiceOption {
	return func(s *userService) { s.aiGateway = newAIGatewayExchange(cfg, authority, tenants) }
}

func WithWorkloadAIGateway(cfg config.AIGatewayConfig, authority aigateway.Authority, tenants CodeQTopicTenantReader, users AIUserTokenValidator) WorkloadIdentityServiceOption {
	return func(s *workloadIdentityService) {
		s.aiGateway = newAIGatewayExchange(cfg, authority, tenants)
		s.aiGateway.users = users
	}
}

func reservedAIAudience(e *aiGatewayExchange, audience string) bool {
	return aigateway.ReservedAudience(audience) || e != nil && e.cfg.StoreAudience != "" && strings.EqualFold(strings.TrimSpace(audience), e.cfg.StoreAudience)
}

func (e *aiGatewayExchange) ready() bool {
	return e != nil && e.cfg.Enabled && e.authority != nil && e.tenants != nil && e.slots != nil && e.limiter != nil && e.cfg.AccessTokenTTLSeconds >= 30 && e.cfg.AccessTokenTTLSeconds <= 300
}

func (e *aiGatewayExchange) tenant(ctx context.Context, id string, now time.Time) (string, error) {
	if e == nil || e.tenants == nil || !tenantIDPattern.MatchString(id) || id == domain.RetiredDefaultTenantID {
		return "", domain.ErrInvalidTenant
	}
	t, err := e.tenants.GetRetained(ctx, id, now)
	if err != nil {
		return "", domain.ErrAuthenticationUnavailable
	}
	if !activeTenant(t, id, now) {
		return "", domain.ErrInvalidTenant
	}
	sum := sha256.Sum256([]byte("codefoundry/tenant-lifetime/v1\x00" + id + "\x00" + t.CreatedAt.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:]), nil
}

func (e *aiGatewayExchange) authorize(ctx context.Context, identity aigateway.Identity, key *rsa.PrivateKey, issuer, kid string, now time.Time) (aigateway.Principal, error) {
	var zero aigateway.Principal
	if !e.ready() || key == nil || issuer == "" || kid == "" {
		return zero, domain.ErrAuthenticationUnavailable
	}
	epoch, err := e.tenant(ctx, identity.TenantID, now)
	if err != nil {
		return zero, err
	}
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		return zero, domain.ErrAuthenticationUnavailable
	}
	claims := jwt.MapClaims{"iss": issuer, "aud": aigateway.AuthorityAudience, "sub": "tikti", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": uuid.NewString(), "ai_identity": identity}
	assertion, err := signAIClaims(key, kid, claims)
	if err != nil {
		return zero, err
	}
	p, err := e.authority.Authorize(ctx, assertion)
	if err != nil {
		if errors.Is(err, aigateway.ErrDenied) {
			return zero, domain.ErrUnauthorizedScope
		}
		return zero, domain.ErrAuthenticationUnavailable
	}
	if p.SchemaVersion != aigateway.IdentityVersion || p.TenantID != identity.TenantID || p.TenantUID != identity.TenantID || p.TenantEpoch != epoch || p.PrincipalKind != identity.Kind || p.Subject == "" {
		return zero, domain.ErrUnauthorizedScope
	}
	if identity.Kind == "User" {
		if p.Subject != identity.Subject || p.Workload != nil || identity.Workload != nil {
			return zero, domain.ErrUnauthorizedScope
		}
	} else {
		w, r := p.Workload, identity.Workload
		if w == nil || r == nil || !domain.ValidWorkloadObjectUID(w.ServiceUID) || w.Issuer != r.Issuer || w.ClusterRef != r.ClusterRef || w.Namespace != r.Namespace || w.ServiceAccount != r.ServiceAccount || w.ServiceAccountUID != r.ServiceAccountUID || w.PodUID != r.PodUID {
			return zero, domain.ErrUnauthorizedScope
		}
		if identity.Kind == "Workload" && p.Subject != "codefoundry:service:"+w.ServiceUID || identity.Kind == "Delegated" && p.Subject != identity.Subject {
			return zero, domain.ErrUnauthorizedScope
		}
	}
	// Mutable tenant withdrawal wins over an earlier callback response.
	if current, err := e.tenant(ctx, identity.TenantID, time.Now().UTC()); err != nil || current != epoch {
		return zero, domain.ErrInvalidTenant
	}
	return p, nil
}

func signAIClaims(key *rsa.PrivateKey, kid string, claims jwt.MapClaims) (string, error) {
	if key == nil || kid == "" {
		return "", domain.ErrAuthenticationUnavailable
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	if err != nil {
		return "", domain.ErrAuthenticationUnavailable
	}
	return raw, nil
}

func aiPrincipalClaims(p aigateway.Principal, issuer string, scopes []string, now time.Time, ttl time.Duration) jwt.MapClaims {
	return jwt.MapClaims{"iss": issuer, "aud": aigateway.Audience, "sub": p.Subject, "tid": p.TenantID, "tenant_uid": p.TenantUID, "tenant_epoch": p.TenantEpoch, "principal_kind": p.PrincipalKind, "scope": strings.Join(scopes, " "), "iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": uuid.NewString()}
}

func (s *userService) aiUserEffectiveScopes(ctx context.Context, user *domain.User, tenant string, requested []string) ([]string, error) {
	a, err := s.resolveTenantScopedAIAuthorization(ctx, user, tenant)
	if err != nil {
		return nil, err
	}
	if s.clientSvc == nil {
		return nil, domain.ErrInvalidAudience
	}
	c, err := s.clientSvc.GetClient(ctx, tenant, aigateway.Audience)
	// Only the Tikti-managed, credential-free AI audience is an activation
	// marker; unmanaged look-alikes fail closed.
	if err != nil || c == nil || c.Id != aigateway.Audience || !domain.IsManagedAIGatewayAudience(tenant, c) {
		return nil, domain.ErrInvalidAudience
	}
	ceiling, valid := aigateway.Scopes(c.DefaultScopes)
	if !valid {
		return nil, domain.ErrUnauthorizedScope
	}
	out := make([]string, 0, len(requested))
	for _, scope := range requested {
		permission := scope
		if scope == aigateway.UsageScope {
			permission = "code-admin:ai:read"
		}
		if slices.Contains(ceiling, scope) && slices.Contains(a.permissions, permission) {
			out = append(out, scope)
		}
	}
	if len(out) == 0 {
		return nil, domain.ErrUnauthorizedScope
	}
	return out, nil
}
func (s *userService) aiUserPermissions(ctx context.Context, user *domain.User, tenant string, scopes []string) error {
	granted, err := s.aiUserEffectiveScopes(ctx, user, tenant, scopes)
	if err != nil {
		return err
	}
	if !slices.Equal(granted, scopes) {
		return domain.ErrUnauthorizedScope
	}
	return nil
}

func (s *userService) exchangeAIUser(ctx context.Context, r domain.TokenExchangeReq, user *domain.User, source jwt.MapClaims) (*domain.TokenExchangeResp, error) {
	e := s.aiGateway
	requested := r.Scopes
	if r.ScopeCeilingV1 != nil {
		requested = r.ScopeCeilingV1
	}
	scopes, valid := aigateway.Scopes(requested)
	if !e.ready() || r.Audience != aigateway.Audience {
		return nil, domain.ErrInvalidAudience
	}
	if !valid || len(r.EventTypes) > 0 || r.DiscoverTenantTargetsV1 || r.DiscoverTenantTargetsV2 || r.ScopeCeilingV1 != nil && len(r.Scopes) != 0 || r.TTLSeconds < 0 {
		return nil, domain.ErrInvalidArgument
	}
	if r.ScopeCeilingV1 != nil {
		var err error
		scopes, err = s.aiUserEffectiveScopes(ctx, user, r.TenantID, scopes)
		if err != nil {
			return nil, err
		}
	} else if err := s.aiUserPermissions(ctx, user, r.TenantID, scopes); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	ttl := time.Duration(e.cfg.AccessTokenTTLSeconds) * time.Second
	if r.TTLSeconds > 0 {
		ttl = min(ttl, time.Duration(r.TTLSeconds)*time.Second)
	}
	exp, err := source.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, domain.ErrInvalidToken
	}
	ttl = min(ttl, exp.Time.Sub(now).Truncate(time.Second))
	if ttl < time.Second {
		return nil, domain.ErrInvalidToken
	}
	key, err := s.getRSAPrivateKey()
	priv, ok := key.(*rsa.PrivateKey)
	if err != nil || !ok {
		return nil, domain.ErrAuthenticationUnavailable
	}
	p, err := e.authorize(ctx, aigateway.Identity{SchemaVersion: aigateway.IdentityVersion, Kind: "User", Subject: user.Id, TenantID: r.TenantID, Scopes: scopes}, priv, s.issuerBaseURL, s.jwksKeyID, now)
	if err != nil {
		return nil, err
	}
	claims := aiPrincipalClaims(p, s.issuerBaseURL, scopes, now, ttl)
	claims["ver"] = user.TokenVersion
	raw, err := signAIClaims(priv, s.jwksKeyID, claims)
	if err != nil {
		return nil, err
	}
	return &domain.TokenExchangeResp{AccessToken: raw, TokenType: "Bearer", ExpiresIn: int(ttl / time.Second), Scopes: scopes}, nil
}

// ValidateAIAccessToken is a separate current-authority contract. It deliberately
// does not use the legacy Kubernetes-subject shortcut or return raw JWT claims.
func (s *userService) ValidateAIAccessToken(ctx context.Context, raw string) (aigateway.Claims, error) {
	var c aigateway.Claims
	e := s.aiGateway
	if !e.ready() || len(raw) > 16384 || strings.ContainsAny(raw, " \t\r\n") {
		return c, domain.ErrInvalidToken
	}
	key, err := s.getRSAPrivateKey()
	priv, ok := key.(*rsa.PrivateKey)
	if err != nil || !ok {
		return c, domain.ErrAuthenticationUnavailable
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return c, domain.ErrInvalidToken
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || aigateway.Decode(data, &c) != nil {
		return c, domain.ErrInvalidToken
	}
	now := time.Now().UTC().Truncate(time.Second)
	token, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		if token.Header["kid"] != s.jwksKeyID {
			return nil, domain.ErrInvalidToken
		}
		return &priv.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.issuerBaseURL), jwt.WithAudience(aigateway.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	scopes, valid := aigateway.Scopes(strings.Split(c.Scope, " "))
	if err != nil || !token.Valid || !valid || strings.Join(scopes, " ") != c.Scope || c.Audience != aigateway.Audience || c.IssuedAt <= 0 || c.IssuedAt > now.Unix() || c.ExpiresAt <= now.Unix() || c.ExpiresAt-c.IssuedAt > 300 || c.ID == "" {
		return aigateway.Claims{}, domain.ErrInvalidToken
	}
	identity := aigateway.Identity{SchemaVersion: aigateway.IdentityVersion, Kind: c.PrincipalKind, Subject: c.Subject, TenantID: c.TenantID, Scopes: scopes}
	switch c.PrincipalKind {
	case "User", "Delegated":
		byID, ok := s.repo.(repository.UserIDRepository)
		if !ok || c.Version == nil || *c.Version < 0 || c.Workload != nil || (c.PrincipalKind == "User") != (c.Actor == nil) {
			return aigateway.Claims{}, domain.ErrInvalidToken
		}
		u, err := byID.FindByID(ctx, c.Subject)
		if err != nil || u == nil || u.Id != c.Subject || u.Status != domain.UserStatusActive || u.PasswordChangeRequired || u.TokenVersion != *c.Version {
			return aigateway.Claims{}, domain.ErrInvalidToken
		}
		if err := s.aiUserPermissions(ctx, u, c.TenantID, scopes); err != nil {
			return aigateway.Claims{}, err
		}
		if c.Actor != nil {
			a := c.Actor
			if a.Subject != "codefoundry:service:"+a.ServiceUID {
				return aigateway.Claims{}, domain.ErrInvalidToken
			}
			identity.Workload = &aigateway.WorkloadRequest{Issuer: a.Issuer, ClusterRef: a.ClusterRef, Namespace: a.Namespace, ServiceAccount: a.ServiceAccount, ServiceAccountUID: a.ServiceAccountUID, PodUID: a.PodUID}
		}
	case "Workload":
		if c.Version != nil || c.Actor != nil || c.Workload == nil || c.Subject != "codefoundry:service:"+c.Workload.ServiceUID {
			return aigateway.Claims{}, domain.ErrInvalidToken
		}
		w := c.Workload
		identity.Subject = "system:serviceaccount:" + w.Namespace + ":" + w.ServiceAccount
		identity.Workload = &aigateway.WorkloadRequest{Issuer: w.Issuer, ClusterRef: w.ClusterRef, Namespace: w.Namespace, ServiceAccount: w.ServiceAccount, ServiceAccountUID: w.ServiceAccountUID, PodUID: w.PodUID}
	default:
		return aigateway.Claims{}, domain.ErrInvalidToken
	}
	p, err := e.authorize(ctx, identity, priv, s.issuerBaseURL, s.jwksKeyID, now)
	if err != nil {
		return aigateway.Claims{}, err
	}
	if p.Subject != c.Subject || p.TenantUID != c.TenantUID || p.TenantEpoch != c.TenantEpoch {
		return aigateway.Claims{}, domain.ErrInvalidToken
	}
	if c.Workload != nil && *p.Workload != *c.Workload || c.Actor != nil && p.Workload.ServiceUID != c.Actor.ServiceUID {
		return aigateway.Claims{}, domain.ErrInvalidToken
	}
	return c, nil
}
