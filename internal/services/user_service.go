package services

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// UserService exposes all account-management operations used by the controllers.
type UserService interface {
	SignIn(ctx context.Context, req domain.SignInReq) (*domain.SignInResp, error)
	SignInWithOobCode(ctx context.Context, req domain.SignInWithOobCodeReq) (*domain.SignInResp, error)
	Lookup(ctx context.Context, req domain.LookupReq) (*domain.LookupResp, error)
	TokenExchange(ctx context.Context, req domain.TokenExchangeReq) (*domain.TokenExchangeResp, error)
	JWKS(ctx context.Context) (map[string]any, error)
	ValidateIDToken(ctx context.Context, tokenString string, issuer string, audience string) (jwt.MapClaims, error)
	ValidateAccessToken(ctx context.Context, tokenString string, issuer string, audience string) (jwt.MapClaims, error)
	SetStatus(ctx context.Context, email string, status string) (*domain.StatusResp, error)
	RevokeTokens(ctx context.Context, email string, tenantID string, scope string) (*domain.RevokeResp, error)
	UpdateUser(ctx context.Context, req domain.UpdateReq) (*domain.UpdateResp, error)
	DeleteUser(ctx context.Context, req domain.DeleteReq) error
	SendOob(ctx context.Context, req domain.SendOobReq) (*domain.SendOobResp, error)
	SendOobForTenant(ctx context.Context, tenantID string, req domain.SendOobReq) (*domain.SendOobTenantResp, error)
	ResetPassword(ctx context.Context, req domain.ResetPwdReq) error
}

// userService is the concrete UserService backed by the repository and JWT utilities.
type userService struct {
	repo                              repository.UserRepository
	membershipRepo                    repository.MembershipRepository
	exactMembershipRepo               repository.ExactMembershipRepository
	directoryAccess                   repository.IdentityDirectoryRepository
	authenticationAttempts            authenticationAttemptLimiter
	authenticationRateLimits          config.AuthenticationRateLimitsConfig
	verifyPassword                    func(string, string) bool
	tenantRepo                        repository.TenantRepository
	tenantScopedTokenClaimsV1         bool
	tenantScopedTokenAllowlist        map[string]struct{}
	tenantTargetDiscoveryV2           bool
	tenantTargetDiscoveryV2Principals map[string]struct{}
	platformAdministrators            map[string]struct{}
	platformAuthorityConfigured       bool
	jwtSecret                         string
	issuerBaseURL                     string
	defaultAudience                   string
	jwksPrivateKey                    string
	jwksKeyID                         string
	roleSvc                           RoleService
	clientSvc                         ClientService
	tenantDiscoveryMetrics            *TenantDiscoveryMetrics
	rsaOnce                           sync.Once
	rsaKey                            interface{}
	rsaErr                            error
}

type UserServiceOption func(*userService)

type authenticationAttemptLimiter interface {
	AllowAuthenticationAttempt(context.Context, string, string, int, time.Duration) (bool, error)
}

const (
	platformAuthorityOriginClaim = "tikti_platform_authority_origin"
	platformAuthorityOriginSAML  = "saml-allowlist-v1"
)

// WithIdentityDirectoryAccess makes mutable direct and inherited assignments
// the token authority after the startup backfill. Legacy memberships remain a
// migration input only.
func WithIdentityDirectoryAccess(access repository.IdentityDirectoryRepository) UserServiceOption {
	return func(service *userService) {
		service.directoryAccess = access
		service.authenticationAttempts = access
	}
}

// WithPasswordAttemptLimiter injects the distributed authentication throttle
// independently of the wider directory contract.
func WithPasswordAttemptLimiter(limiter authenticationAttemptLimiter) UserServiceOption {
	return func(service *userService) { service.authenticationAttempts = limiter }
}

func WithAuthenticationRateLimits(limits config.AuthenticationRateLimitsConfig) UserServiceOption {
	return func(service *userService) {
		service.authenticationRateLimits = effectiveAuthenticationRateLimits(limits)
	}
}

// WithCurrentPlatformAdministrators binds SAML platform authority to the
// current server-side allowlist. Passing an empty slice intentionally enables
// the authority and revokes every previously allowlisted SAML administrator.
func WithCurrentPlatformAdministrators(administrators []config.SAMLPlatformAdministrator) UserServiceOption {
	configured := append([]config.SAMLPlatformAdministrator(nil), administrators...)
	return func(service *userService) {
		service.platformAuthorityConfigured = true
		service.platformAdministrators = make(map[string]struct{}, len(configured))
		for _, administrator := range configured {
			key := currentPlatformAdministratorKey(administrator.TenantID, administrator.Email)
			if key != "" {
				service.platformAdministrators[key] = struct{}{}
			}
		}
	}
}

// NewUserService builds a service instance that signs JWTs with the provided secret.
func NewUserService(r repository.UserRepository, membershipRepo repository.MembershipRepository, roleSvc RoleService, clientSvc ClientService, jwtSecret string, issuerBaseURL string, defaultAudience string, jwksPrivateKey string, jwksKeyID string, options ...UserServiceOption) UserService {
	exactMembershipRepo, _ := membershipRepo.(repository.ExactMembershipRepository)
	service := &userService{
		repo:                     r,
		membershipRepo:           membershipRepo,
		exactMembershipRepo:      exactMembershipRepo,
		roleSvc:                  roleSvc,
		clientSvc:                clientSvc,
		jwtSecret:                jwtSecret,
		issuerBaseURL:            issuerBaseURL,
		defaultAudience:          defaultAudience,
		jwksPrivateKey:           jwksPrivateKey,
		jwksKeyID:                jwksKeyID,
		verifyPassword:           utils.VerifyPassword,
		authenticationRateLimits: config.DefaultAuthenticationRateLimits(),
	}
	for _, option := range options {
		if option != nil {
			option(service)
		}
	}
	return service
}

// SignIn verifies credentials and returns a signed JWT alongside metadata.
func (s *userService) SignIn(ctx context.Context, req domain.SignInReq) (*domain.SignInResp, error) {
	email := normalizeIdentityEmail(req.Email)
	if s.authenticationAttempts != nil {
		limit := s.authenticationRateLimits.Login
		allowed, limitErr := s.allowAuthenticationAttempt(ctx, authenticationBucketPasswordIP, authenticationClientIP(ctx), limit.Requests, time.Duration(limit.WindowSeconds)*time.Second)
		if allowed && limitErr == nil {
			allowed, limitErr = s.allowAuthenticationAttempt(ctx, authenticationBucketPasswordEmail, email, limit.Requests, time.Duration(limit.WindowSeconds)*time.Second)
		}
		if limitErr != nil || !allowed {
			// Preserve one cost-matched password operation even when the request is
			// rejected before directory lookup.
			_ = s.verifyPassword(temporaryPasswordDummyHash, req.Password)
			if !allowed && limitErr == nil {
				return nil, domain.ErrRateLimited
			}
			return nil, domain.ErrInvalidCreds
		}
	}

	u, err := s.repo.FindByEmail(ctx, email)
	eligible := err == nil && u != nil && u.Status == domain.UserStatusActive && passwordCredentialEligible(u)
	passwordHash := temporaryPasswordDummyHash
	if eligible {
		passwordHash = u.Password
	}
	verified := s.verifyPassword(passwordHash, req.Password)
	if !eligible || !verified {
		return nil, domain.ErrInvalidCreds
	}
	if u.PasswordChangeRequired && s.directoryAccess == nil {
		return nil, domain.ErrInvalidCreds
	}
	if u.PasswordChangeRequired {
		return nil, domain.ErrPasswordChangeRequired
	}
	signed, expiresIn, e2 := s.issueIDToken(u, nil)
	if e2 != nil {
		return nil, e2
	}
	return &domain.SignInResp{
		IdToken:   signed,
		Email:     u.Email,
		LocalId:   u.Id,
		ExpiresIn: expiresIn,
	}, nil
}

// SignInWithOobCode authenticates the user using a one-time code delivered via email.
func (s *userService) SignInWithOobCode(ctx context.Context, req domain.SignInWithOobCodeReq) (*domain.SignInResp, error) {
	email := normalizeIdentityEmail(req.Email)
	code := strings.TrimSpace(req.OobCode)
	if email == "" || code == "" {
		return nil, domain.ErrInvalidArgument
	}
	limit := s.authenticationRateLimits.OOBSignIn
	allowed, limitErr := s.allowAuthenticationAttempt(ctx, authenticationBucketOOBSignInIP, authenticationClientIP(ctx), limit.Requests, time.Duration(limit.WindowSeconds)*time.Second)
	if allowed && limitErr == nil {
		allowed, limitErr = s.allowAuthenticationAttempt(ctx, authenticationBucketOOBSignInEmail, email, limit.Requests, time.Duration(limit.WindowSeconds)*time.Second)
	}
	if limitErr != nil {
		return nil, domain.ErrAuthenticationUnavailable
	}
	if !allowed {
		return nil, domain.ErrRateLimited
	}

	oobEmail, err := s.repo.ConsumeOobCode(ctx, code, "EMAIL_SIGNIN")
	if err != nil {
		if errors.Is(err, domain.ErrInvalidOob) {
			return nil, domain.ErrInvalidOob
		}
		return nil, domain.ErrAuthenticationUnavailable
	}
	if !strings.EqualFold(oobEmail, email) {
		return nil, domain.ErrInvalidOob
	}

	u, findErr := s.repo.FindByEmail(ctx, oobEmail)
	if findErr != nil || u == nil {
		return nil, domain.ErrInvalidCreds
	}
	if u.Status != domain.UserStatusActive {
		return nil, domain.ErrInvalidCreds
	}
	if !passwordCredentialEligible(u) {
		return nil, domain.ErrInvalidCreds
	}
	if u.PasswordChangeRequired {
		return nil, domain.ErrPasswordChangeRequired
	}

	signed, expiresIn, tokenErr := s.issueIDToken(u, nil)
	if tokenErr != nil {
		return nil, tokenErr
	}
	return &domain.SignInResp{
		IdToken:   signed,
		Email:     u.Email,
		LocalId:   u.Id,
		ExpiresIn: expiresIn,
	}, nil
}

// Lookup converts an idToken into a LookupResp by pulling the stored user.
func (s *userService) Lookup(ctx context.Context, req domain.LookupReq) (*domain.LookupResp, error) {
	limit := s.authenticationRateLimits.Lookup
	allowed, limitErr := s.allowAuthenticationAttempt(ctx, authenticationBucketLookupAPIKey, authenticationAPIKeyID(ctx), limit.Requests, time.Duration(limit.WindowSeconds)*time.Second)
	if limitErr != nil {
		return nil, domain.ErrAuthenticationUnavailable
	}
	if !allowed {
		return nil, domain.ErrRateLimited
	}
	_, u, err := s.validateCurrentIDToken(ctx, req.IdToken, s.issuerBaseURL, s.defaultAudience)
	if err != nil {
		return nil, err
	}
	return &domain.LookupResp{
		Users: []domain.UserInfo{{
			LocalId: u.Id,
			Email:   u.Email,
			Role:    string(effectiveUserRole(u)),
			Status:  string(u.Status),
			Tenant:  s.resolveTenantID(ctx, u),
		}},
	}, nil
}

// TokenExchange exchanges an idToken for a scoped RS256 access token.
func (s *userService) TokenExchange(ctx context.Context, req domain.TokenExchangeReq) (result *domain.TokenExchangeResp, resultErr error) {
	if strings.TrimSpace(req.TenantID) == domain.RetiredDefaultTenantID {
		return nil, domain.ErrInvalidTenant
	}
	discoveryMetricMode := requestedTenantDiscoveryMode(req)
	if discoveryMetricMode != "" && s.tenantDiscoveryMetrics != nil {
		defer func() {
			authorizedTargets := 0
			if result != nil {
				authorizedTargets = len(result.AuthorizedTenants)
			}
			s.tenantDiscoveryMetrics.observeRequest(discoveryMetricMode, resultErr, authorizedTargets)
		}()
	}
	if strings.TrimSpace(req.IdToken) == "" {
		return nil, domain.ErrInvalidToken
	}
	if strings.TrimSpace(req.Audience) == "" {
		return nil, domain.ErrInvalidAudience
	}

	claims, u, err := s.validateCurrentIDToken(ctx, req.IdToken, s.issuerBaseURL, s.defaultAudience)
	if err != nil {
		return nil, err
	}
	limit := s.authenticationRateLimits.TokenExchange
	allowed, limitErr := s.allowAuthenticationAttempt(ctx, authenticationBucketTokenExchangeUser, u.Id, limit.Requests, time.Duration(limit.WindowSeconds)*time.Second)
	if limitErr != nil {
		return nil, domain.ErrAuthenticationUnavailable
	}
	if !allowed {
		return nil, domain.ErrRateLimited
	}
	strictTarget, protectedTarget := s.tenantScopedTokenTarget(req.TenantID)
	discoveryRequested := req.DiscoverTenantTargetsV1 || req.DiscoverTenantTargetsV2
	platformPrivilege := validatedPlatformPrivilege(u, claims)
	if protectedTarget && strictTarget == "" {
		return nil, domain.ErrInvalidTenant
	}
	if req.ScopeCeilingV1 != nil && !discoveryRequested {
		return nil, domain.ErrInvalidArgument
	}
	if req.DiscoverTenantTargetsV1 && req.DiscoverTenantTargetsV2 {
		return nil, domain.ErrInvalidArgument
	}
	discoveryExchangeV1 := req.DiscoverTenantTargetsV1 && s.tenantScopedTokenClaimsV1 &&
		req.Audience == domain.CodeAdminAudienceClientID
	discoveryExchangeV2 := req.DiscoverTenantTargetsV2 && s.tenantTargetDiscoveryV2 &&
		req.Audience == domain.CodeAdminAudienceClientID
	discoveryExchange := discoveryExchangeV1 || discoveryExchangeV2
	if discoveryRequested && !discoveryExchange {
		return nil, domain.ErrInvalidArgument
	}
	tenantID := strictTarget
	var tenantRoles, tenantPermissions []string
	var discovery tenantDiscoveryAuthorization
	var scopes []string
	if discoveryExchange {
		dynamicTargets := discoveryExchangeV2
		signedHome := claimStringValue(claims, "tid")
		home, directoryPrincipal, homeErr := s.resolveDiscoveryHome(
			ctx, u, signedHome, claimStringValue(claims, "role"), platformPrivilege,
		)
		if homeErr != nil {
			return nil, homeErr
		}
		discovery, err = s.resolveTenantDiscoveryAuthorization(
			ctx, u, req.TenantID, home,
			claimStringValue(claims, "role"), req.ScopeCeilingV1, req.Scopes,
			dynamicTargets, discoveryMetricMode, platformPrivilege, directoryPrincipal,
		)
		if err != nil {
			return nil, err
		}
		tenantID, tenantRoles, scopes = discovery.tenantID, discovery.roles, discovery.scopes
		if tenantID == discovery.principalTenantID && !discovery.directoryPrincipal {
			strictTarget = ""
		} else {
			strictTarget = tenantID
		}
	} else {
		if strictTarget != "" {
			authorization, authErr := s.resolveTenantScopedTokenAuthorization(ctx, u, strictTarget)
			if authErr != nil {
				return nil, authErr
			}
			tenantRoles, tenantPermissions = authorization.roles, authorization.permissions
		} else {
			tenantID = strings.TrimSpace(req.TenantID)
			memberTenants := s.listTenantIDs(ctx, u.Id)
			if tenantID == "" {
				if len(memberTenants) > 0 {
					tenantID = memberTenants[0]
				} else {
					tenantID = derefString(u.CompanyId)
				}
			}
			if tenantID == "" {
				return nil, domain.ErrInvalidTenant
			}
			if len(memberTenants) > 0 && !containsString(memberTenants, tenantID) {
				return nil, domain.ErrInvalidTenant
			}
			if len(memberTenants) == 0 && u.CompanyId != nil && *u.CompanyId != tenantID {
				return nil, domain.ErrInvalidTenant
			}
			if u.CompanyId == nil {
				if s.directoryAccess == nil || !containsString(memberTenants, tenantID) {
					return nil, domain.ErrInvalidTenant
				}
				roles, _, accessErr := s.directoryAccess.GetEffectiveTenantRoles(ctx, u.Id, tenantID)
				if accessErr != nil || len(roles) == 0 {
					return nil, domain.ErrInvalidTenant
				}
				if s.roleSvc == nil {
					return nil, domain.ErrUnauthorizedScope
				}
				permissions, permissionErr := s.roleSvc.ResolvePermissions(ctx, tenantID, roles)
				if permissionErr != nil {
					return nil, domain.ErrUnauthorizedScope
				}
				tenantRoles = append([]string(nil), roles...)
				tenantPermissions = normalizePermissions(permissions)
				strictTarget = tenantID
			}
		}

		scopes = normalizeList(req.Scopes)
		if s.clientSvc != nil {
			client, clientErr := s.clientSvc.GetClient(ctx, tenantID, req.Audience)
			if clientErr != nil {
				return nil, clientErr
			}
			if client == nil || client.Status != "ACTIVE" {
				return nil, domain.ErrInvalidAudience
			}
			if len(scopes) == 0 {
				scopes = append(scopes, client.DefaultScopes...)
			}
			if !subset(scopes, client.DefaultScopes) && len(client.DefaultScopes) > 0 {
				return nil, domain.ErrUnauthorizedScope
			}
		}
		if strictTarget != "" {
			scopes = normalizePermissions(scopes)
			if !subset(scopes, tenantPermissions) {
				return nil, domain.ErrUnauthorizedScope
			}
		} else if len(scopes) > 0 && !s.scopesAllowed(ctx, tenantID, u, scopes, platformPrivilege) {
			return nil, domain.ErrUnauthorizedScope
		}
	}
	if len(scopes) > 0 {
		canonicalScopes, ok := scopepolicy.CanonicalAudienceScopes(scopes)
		if !ok {
			return nil, domain.ErrUnauthorizedScope
		}
		scopes = canonicalScopes
	}

	eventTypes := normalizeList(req.EventTypes)
	if req.Audience == "codeq-worker" && len(eventTypes) == 0 {
		return nil, domain.ErrInvalidArgument
	}

	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 3600
	}
	if ttl > 86400 {
		ttl = 86400
	}
	now := time.Now()
	sourceExpiry, expiryErr := claims.GetExpirationTime()
	if expiryErr != nil || sourceExpiry == nil {
		return nil, domain.ErrInvalidToken
	}
	sourceTTL := int(sourceExpiry.Time.Unix() - now.Unix())
	if sourceTTL <= 0 {
		return nil, domain.ErrInvalidToken
	}
	if ttl > sourceTTL {
		ttl = sourceTTL
	}
	authenticationMethods, validAMR := canonicalAuthenticationMethods(claims)
	if !validAMR {
		return nil, domain.ErrInvalidToken
	}

	// This endpoint exchanges a human browser session. Its subject is always
	// the authenticated directory principal; workload delegation has a
	// separate projected-service-account exchange and must never be smuggled
	// through a caller-controlled claim.
	subject := u.Id

	key, err := s.getRSAPrivateKey()
	if err != nil {
		return nil, err
	}

	scopeString := strings.Join(scopes, " ")
	role := effectiveUserRole(u, platformPrivilege)
	claimsOut := jwt.MapClaims{
		"iss":   s.issuerBaseURL,
		"aud":   req.Audience,
		"sub":   subject,
		"email": u.Email,
		"role":  string(role),
		"tid":   tenantID,
		"ver":   u.TokenVersion,
		"iat":   now.Unix(),
		"exp":   now.Unix() + int64(ttl),
		"jti":   uuid.NewString(),
	}
	if u.CompanyId != nil {
		if principalTenantID := strings.TrimSpace(*u.CompanyId); principalTenantID != "" {
			claimsOut["principal_tid"] = principalTenantID
		}
	}
	if strictTarget != "" {
		delete(claimsOut, "role")
		claimsOut["roles"] = tenantRoles
	}
	if strictTarget == "" && role == domain.RoleAdmin && containsString(scopes, domain.PlatformTenantAdminScope) {
		claimsOut[domain.PlatformPrivilegeClaim] = domain.PlatformPrivilegeAdmin
	}
	if platformPrivilege == domain.PlatformPrivilegeAdmin {
		// This private provenance marker is not an authorization input for
		// downstream services. Tikti uses it only to re-evaluate current
		// server-side allowlist authority when the bearer token is reused.
		claimsOut[platformAuthorityOriginClaim] = platformAuthorityOriginSAML
	}
	if scopeString != "" {
		claimsOut["scope"] = scopeString
	}
	if len(eventTypes) > 0 {
		claimsOut["eventTypes"] = eventTypes
	}
	if len(authenticationMethods) > 0 {
		claimsOut["amr"] = authenticationMethods
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claimsOut)
	if s.jwksKeyID != "" {
		token.Header["kid"] = s.jwksKeyID
	}
	signed, err := token.SignedString(key)
	if err != nil {
		return nil, err
	}
	response := &domain.TokenExchangeResp{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   ttl,
	}
	if discoveryExchange {
		response.PrincipalTenantID = discovery.principalTenantID
		response.AuthorizedTenants = append([]string(nil), discovery.authorizedTenants...)
		response.Scopes = append([]string(nil), discovery.scopes...)
	}
	return response, nil
}

// ValidateIDToken validates an HS256 browser session and enforces the current
// user status and token version. SAML and password sign-in both issue this
// token shape, so callers do not need to branch on the authentication method.
func (s *userService) ValidateIDToken(ctx context.Context, tokenString string, issuer string, audience string) (jwt.MapClaims, error) {
	claims, _, err := s.validateCurrentIDToken(ctx, tokenString, issuer, audience)
	return claims, err
}

func (s *userService) validateCurrentIDToken(ctx context.Context, tokenString string, issuer string, audience string) (jwt.MapClaims, *domain.User, error) {
	claims, err := utils.ParseToken(tokenString, s.jwtSecret)
	if err != nil {
		return nil, nil, domain.ErrInvalidToken
	}
	if issuer != "" {
		claimIssuer, _ := claims["iss"].(string)
		if claimIssuer != issuer {
			return nil, nil, domain.ErrInvalidToken
		}
	}
	if !tokenHasAudience(claims, audience) {
		return nil, nil, domain.ErrInvalidToken
	}

	subject, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	if strings.TrimSpace(subject) == "" || strings.TrimSpace(email) == "" {
		return nil, nil, domain.ErrInvalidToken
	}
	user, repoErr := s.resolveCurrentTokenUser(ctx, subject, email)
	if repoErr != nil {
		return nil, nil, repoErr
	}
	_, subjectAuthoritative := s.repo.(repository.UserIDRepository)
	if subjectAuthoritative && user.AuthSource == domain.AuthSourceSAML && user.CompanyId != nil {
		if claimStringValue(claims, "tid") != strings.TrimSpace(*user.CompanyId) {
			return nil, nil, domain.ErrInvalidToken
		}
	} else if subjectAuthoritative && user.AuthSource == domain.AuthSourceSAML && claimStringValue(claims, "tid") != "" {
		return nil, nil, domain.ErrInvalidToken
	}
	if tenantID := claimStringValue(claims, "tid"); tenantID != "" && s.tenantRepo != nil {
		tenant, tenantErr := s.tenantRepo.Get(ctx, tenantID)
		if tenantErr != nil || tenant == nil || tenant.Id != tenantID || tenant.Status != domain.TenantStatusActive {
			return nil, nil, domain.ErrInvalidToken
		}
	}
	if user.Status != domain.UserStatusActive {
		return nil, nil, domain.ErrInvalidCreds
	}
	if user.PasswordChangeRequired {
		return nil, nil, domain.ErrPasswordChangeRequired
	}
	if !s.currentPlatformAuthorityValid(user, claims) {
		return nil, nil, domain.ErrInvalidToken
	}
	version, ok := tokenVersion(claims)
	if !ok || version != user.TokenVersion {
		return nil, nil, domain.ErrInvalidToken
	}
	return claims, user, nil
}

// resolveCurrentTokenUser binds a signed human token to its immutable subject.
// Production repositories implement UserIDRepository, including tenant-local
// SAML principals. The email lookup is only a compatibility seam for older
// in-memory implementations and still has to match both signed identifiers.
func (s *userService) resolveCurrentTokenUser(ctx context.Context, subject, email string) (*domain.User, error) {
	if strings.TrimSpace(subject) == "" || strings.TrimSpace(email) == "" {
		return nil, domain.ErrInvalidToken
	}
	if byID, ok := s.repo.(repository.UserIDRepository); ok {
		user, err := byID.FindByID(ctx, subject)
		if err != nil {
			return nil, domain.ErrInvalidToken
		}
		if user == nil {
			return nil, domain.ErrNotFound
		}
		if user.Id != subject || !strings.EqualFold(user.Email, email) {
			return nil, domain.ErrInvalidToken
		}
		return user, nil
	}
	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	if user == nil {
		return nil, domain.ErrNotFound
	}
	if subject != user.Id && !strings.EqualFold(subject, user.Email) || !strings.EqualFold(user.Email, email) {
		return nil, domain.ErrInvalidToken
	}
	return user, nil
}

// ValidateAccessToken validates an RS256 access token. User tokens enforce the
// current token version; short-lived workload tokens use their verified
// Kubernetes ServiceAccount subject and binding-time authorization instead.
func (s *userService) ValidateAccessToken(ctx context.Context, tokenString string, issuer string, audience string) (jwt.MapClaims, error) {
	key, err := s.getRSAPrivateKey()
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid rsa key")
	}
	claims, err := utils.ValidateRS256(tokenString, &priv.PublicKey, issuer, audience)
	if err != nil {
		return nil, err
	}
	subject, _ := claims["sub"].(string)
	if workload, ok := domain.ParseWorkloadSubject(subject); ok && workload.Subject == subject {
		if strings.TrimSpace(claimStringValue(claims, "tid")) == "" {
			return nil, domain.ErrInvalidToken
		}
		return claims, nil
	}
	version, ok := tokenVersion(claims)
	if !ok {
		return nil, domain.ErrInvalidToken
	}
	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	if strings.TrimSpace(sub) == "" || strings.TrimSpace(email) == "" {
		return nil, domain.ErrInvalidToken
	}
	u, resolveErr := s.resolveCurrentTokenUser(ctx, sub, email)
	if resolveErr != nil {
		return nil, resolveErr
	}
	_, subjectAuthoritative := s.repo.(repository.UserIDRepository)
	if subjectAuthoritative && u.AuthSource == domain.AuthSourceSAML && (u.CompanyId == nil || claimStringValue(claims, "principal_tid") != strings.TrimSpace(*u.CompanyId)) {
		return nil, domain.ErrInvalidToken
	}
	if u.Status != domain.UserStatusActive {
		return nil, domain.ErrInvalidCreds
	}
	if u.PasswordChangeRequired {
		return nil, domain.ErrPasswordChangeRequired
	}
	if !s.currentPlatformAuthorityValid(u, claims) {
		return nil, domain.ErrInvalidToken
	}
	if u.TokenVersion != version {
		return nil, domain.ErrInvalidToken
	}
	if err := s.validateCurrentAccessTokenTarget(ctx, claims); err != nil {
		return nil, domain.ErrInvalidToken
	}
	if err := s.validateCurrentAccessTokenAuthority(ctx, u, claims); err != nil {
		return nil, domain.ErrInvalidToken
	}
	return claims, nil
}

// validateCurrentAccessTokenTarget re-evaluates the mutable tenant and
// audience-client authority on every bearer-token use. An access token is a
// short-lived proof of the authority that existed when it was issued; it must
// not outlive a disabled tenant/client or scopes removed from that client.
func (s *userService) validateCurrentAccessTokenTarget(ctx context.Context, claims jwt.MapClaims) error {
	tenantID := claimStringValue(claims, "tid")
	if !validRoleTenantID(tenantID) {
		return domain.ErrInvalidToken
	}
	if s.tenantRepo != nil {
		tenant, err := s.tenantRepo.Get(ctx, tenantID)
		if err != nil || tenant == nil || tenant.Id != tenantID || tenant.Status != domain.TenantStatusActive {
			return domain.ErrInvalidToken
		}
	}
	if s.clientSvc == nil {
		return nil
	}
	audience, ok := claims["aud"].(string)
	if !ok || strings.TrimSpace(audience) == "" || audience != strings.TrimSpace(audience) {
		return domain.ErrInvalidToken
	}
	client, err := s.clientSvc.GetClient(ctx, tenantID, audience)
	if err != nil || client == nil || client.Id != audience || client.TenantId != tenantID || client.Status != domain.ClientStatusActive {
		return domain.ErrInvalidToken
	}
	signedScopes := strings.Fields(claimStringValue(claims, "scope"))
	if len(signedScopes) == 0 {
		return nil
	}
	canonicalScopes, valid := scopepolicy.CanonicalAudienceScopes(signedScopes)
	if !valid {
		return domain.ErrInvalidToken
	}
	currentScopes, valid := scopepolicy.CanonicalAudienceScopes(client.DefaultScopes)
	if !valid || !subset(canonicalScopes, currentScopes) {
		return domain.ErrInvalidToken
	}
	return nil
}

func (s *userService) currentPlatformAuthorityValid(user *domain.User, claims jwt.MapClaims) bool {
	claimedPrivilege := claimStringValue(claims, domain.PlatformPrivilegeClaim)
	authorityOrigin := claimStringValue(claims, platformAuthorityOriginClaim)
	if claimedPrivilege != "" && claimedPrivilege != domain.PlatformPrivilegeAdmin {
		return false
	}
	if authorityOrigin != "" && authorityOrigin != platformAuthorityOriginSAML {
		return false
	}
	if user == nil || user.AuthSource != domain.AuthSourceSAML {
		return authorityOrigin == "" && (claimedPrivilege == "" || user != nil && user.Role == domain.RoleAdmin)
	}
	usesPlatformAuthority := user.Role == domain.RoleAdmin || claimedPrivilege == domain.PlatformPrivilegeAdmin || authorityOrigin == platformAuthorityOriginSAML
	if !usesPlatformAuthority {
		return true
	}
	if user.Role != domain.RoleAdmin || user.CompanyId == nil {
		return false
	}
	if !s.platformAuthorityConfigured {
		// Compatibility seam for isolated service tests. NewApplication always
		// enables the server authority, including when its allowlist is empty.
		return true
	}
	_, allowed := s.platformAdministrators[currentPlatformAdministratorKey(*user.CompanyId, user.Email)]
	return allowed
}

func currentPlatformAdministratorKey(tenantID, email string) string {
	tenantID = strings.TrimSpace(tenantID)
	email = strings.ToLower(strings.TrimSpace(email))
	if tenantID == "" || email == "" {
		return ""
	}
	return tenantID + "\x00" + email
}

// validateCurrentAccessTokenAuthority prevents an already-issued tenant token
// from retaining roles after a direct assignment, group membership, group
// status, group assignment, or role definition changes. Tokens without the
// explicit roles claim use the legacy/home authority path and continue to be
// governed by tokenVersion and the signed role/provenance claims.
func (s *userService) validateCurrentAccessTokenAuthority(ctx context.Context, user *domain.User, claims jwt.MapClaims) error {
	rawRoles, tenantScoped := claims["roles"]
	if !tenantScoped {
		return nil
	}
	platformAuthority := claimStringValue(claims, platformAuthorityOriginClaim) == platformAuthorityOriginSAML
	signedRoles, valid := canonicalAccessTokenRoles(rawRoles)
	if rawRoles == nil && platformAuthority {
		signedRoles, valid = []string{}, true
	}
	if !valid {
		return domain.ErrInvalidToken
	}
	tenantID := claimStringValue(claims, "tid")
	if !validRoleTenantID(tenantID) {
		return domain.ErrInvalidToken
	}
	var currentRoles []string
	if platformAuthority && len(signedRoles) == 0 {
		// Cross-tenant SAML platform authority is allowlist-derived and never
		// manufactures a workload assignment. Its current authority is checked
		// above against the server allowlist, not against target membership.
		currentRoles = []string{}
	} else if s.directoryAccess == nil {
		if len(signedRoles) != 0 {
			return domain.ErrInvalidToken
		}
	} else {
		var err error
		currentRoles, err = s.accessTenantRoles(ctx, user.Id, tenantID)
		if err != nil || !slices.Equal(currentRoles, signedRoles) {
			return domain.ErrInvalidToken
		}
	}
	var authorization tenantScopedTokenAuthorization
	if len(currentRoles) > 0 {
		if s.roleSvc == nil {
			return domain.ErrInvalidToken
		}
		var resolvable bool
		authorization, resolvable = s.resolveMembershipRoleAuthorization(ctx, tenantID, currentRoles)
		if !resolvable {
			return domain.ErrInvalidToken
		}
	}

	signedScopes := strings.Fields(claimStringValue(claims, "scope"))
	if len(signedScopes) == 0 {
		return nil
	}
	canonicalScopes, valid := scopepolicy.CanonicalAudienceScopes(signedScopes)
	if !valid {
		return domain.ErrInvalidToken
	}
	currentAuthority := append([]string(nil), authorization.permissions...)
	if authorization.legacyCreatorAdministrator {
		currentAuthority = append(currentAuthority, tenantSecretReadScope, tenantSecretWriteScope)
	}
	if platformAuthority {
		currentAuthority = append(currentAuthority, homeAuthority(
			user, string(domain.RoleAdmin), canonicalScopes, domain.PlatformPrivilegeAdmin,
		)...)
	}
	if user.CompanyId != nil {
		platformPrivilege := issuablePlatformPrivilege(user, claimStringValue(claims, domain.PlatformPrivilegeClaim))
		currentRole := string(effectiveUserRole(user, platformPrivilege))
		currentAuthority = append(currentAuthority, homeGlobalAuthority(user, currentRole, canonicalScopes, platformPrivilege)...)
	}
	if !subset(canonicalScopes, normalizePermissions(currentAuthority)) {
		return domain.ErrInvalidToken
	}
	return nil
}

func canonicalAccessTokenRoles(raw any) ([]string, bool) {
	var roles []string
	switch values := raw.(type) {
	case []interface{}:
		roles = make([]string, 0, len(values))
		for _, value := range values {
			role, ok := value.(string)
			if !ok {
				return nil, false
			}
			roles = append(roles, role)
		}
	case []string:
		roles = append([]string(nil), values...)
	default:
		return nil, false
	}
	canonical, valid := canonicalMembershipRoles(roles)
	return canonical, valid && slices.Equal(roles, canonical)
}

func claimStringValue(claims jwt.MapClaims, key string) string {
	value, _ := claims[key].(string)
	return value
}

func canonicalAuthenticationMethods(claims jwt.MapClaims) ([]string, bool) {
	raw, exists := claims["amr"]
	if !exists {
		return nil, true
	}
	var values []string
	switch typed := raw.(type) {
	case []interface{}:
		values = make([]string, 0, len(typed))
		for _, item := range typed {
			value, ok := item.(string)
			if !ok {
				return nil, false
			}
			values = append(values, value)
		}
	case []string:
		values = append([]string(nil), typed...)
	default:
		return nil, false
	}
	if len(values) == 0 || len(values) > 16 {
		return nil, false
	}
	seen := make(map[string]struct{}, len(values))
	canonical := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || len(value) > 64 {
			return nil, false
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		canonical = append(canonical, value)
	}
	sort.Strings(canonical)
	return canonical, len(canonical) > 0
}

func tokenVersion(claims jwt.MapClaims) (int, bool) {
	rawVersion, exists := claims["ver"]
	if !exists {
		return 0, false
	}
	version, ok := rawVersion.(float64)
	if !ok || version < 0 || version > 1<<31 || version != float64(int(version)) {
		return 0, false
	}
	return int(version), true
}

func tokenHasAudience(claims jwt.MapClaims, audience string) bool {
	if strings.TrimSpace(audience) == "" {
		return true
	}
	rawAudience, exists := claims["aud"]
	if !exists {
		return false
	}
	switch values := rawAudience.(type) {
	case string:
		return values == audience
	case []interface{}:
		for _, value := range values {
			if item, ok := value.(string); ok && item == audience {
				return true
			}
		}
	case []string:
		for _, value := range values {
			if value == audience {
				return true
			}
		}
	}
	return false
}

// JWKS returns the current JSON Web Key Set for RS256 verification.
func (s *userService) JWKS(ctx context.Context) (map[string]any, error) {
	key, err := s.getRSAPrivateKey()
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid rsa key")
	}
	jwks, err := utils.BuildJWKS(priv, s.jwksKeyID)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if b, err := jwks.Marshal(); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out, nil
}

func (s *userService) SetStatus(ctx context.Context, email string, status string) (*domain.StatusResp, error) {
	email = strings.TrimSpace(email)
	status = strings.TrimSpace(strings.ToUpper(status))
	if email == "" || status == "" {
		return nil, domain.ErrInvalidArgument
	}
	var st domain.UserStatus
	switch status {
	case string(domain.UserStatusActive):
		st = domain.UserStatusActive
	case string(domain.UserStatusInactive):
		st = domain.UserStatusInactive
	case string(domain.UserStatusSuspended):
		st = domain.UserStatusSuspended
	default:
		return nil, domain.ErrInvalidArgument
	}
	u, err := s.repo.SetStatus(ctx, email, st)
	if err != nil {
		return nil, err
	}
	return &domain.StatusResp{
		LocalId: u.Id,
		Email:   u.Email,
		Status:  string(u.Status),
	}, nil
}

func (s *userService) RevokeTokens(ctx context.Context, email string, tenantID string, scope string) (*domain.RevokeResp, error) {
	email = strings.TrimSpace(email)
	tenantID = strings.TrimSpace(tenantID)
	scope = strings.TrimSpace(strings.ToLower(scope))

	if email == "" {
		return nil, domain.ErrInvalidArgument
	}
	if scope == "" {
		scope = "global"
	}
	// TokenVersion is stored on the global user record. Until a separately
	// versioned tenant-session model exists, accepting tenantId/scope=tenant
	// would silently perform a global revocation and misrepresent the result.
	if scope != "global" || tenantID != "" {
		return nil, domain.ErrInvalidArgument
	}

	ver, u, err := s.repo.IncrementTokenVersion(ctx, email)
	if err != nil {
		return nil, err
	}
	return &domain.RevokeResp{
		LocalId:      u.Id,
		Email:        u.Email,
		TokenVersion: ver,
		RevokedAt:    time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// RevokeIDTokenSubject revokes browser sessions by the signed, immutable
// subject. This also covers tenant-local federated principals that are not
// indexed by global email.
func (s *userService) RevokeIDTokenSubject(ctx context.Context, subject string) error {
	byID, ok := s.repo.(repository.UserIDRepository)
	if !ok || strings.TrimSpace(subject) == "" {
		return domain.ErrInvalidArgument
	}
	_, _, err := byID.IncrementTokenVersionByID(ctx, subject)
	return err
}

func (s *userService) getRSAPrivateKey() (interface{}, error) {
	s.rsaOnce.Do(func() {
		key, err := utils.ParseRSAPrivateKey(s.jwksPrivateKey)
		if err != nil {
			s.rsaErr = err
			return
		}
		s.rsaKey = key
	})
	if s.rsaErr != nil {
		return nil, s.rsaErr
	}
	if s.rsaKey == nil {
		return nil, errors.New("rsa private key missing")
	}
	return s.rsaKey, nil
}

func (s *userService) scopesAllowed(ctx context.Context, tenantID string, u *domain.User, scopes []string, platformPrivilege ...string) bool {
	if u == nil {
		return false
	}
	if len(scopes) > 0 {
		canonicalScopes, ok := scopepolicy.CanonicalAudienceScopes(scopes)
		if !ok {
			return false
		}
		scopes = canonicalScopes
	}
	role := effectiveUserRole(u, platformPrivilege...)
	if role == domain.RoleAdmin {
		return true
	}
	if role == domain.RoleCompanyAdmin {
		return !containsString(scopes, domain.PlatformTenantAdminScope)
	}
	roles := []string{string(role)}
	if s.directoryAccess != nil {
		if effective, _, err := s.directoryAccess.GetEffectiveTenantRoles(ctx, u.Id, tenantID); err == nil {
			roles = append(roles, effective...)
		}
	} else if s.membershipRepo != nil {
		if m, _ := s.membershipRepo.Get(ctx, tenantID, u.Id); m != nil {
			roles = append(roles, m.Roles...)
		}
	}
	allowed := map[string]struct{}{}
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		switch r {
		case string(domain.RoleCompanyEmployee):
			for _, p := range []string{"codeq:claim", "codeq:heartbeat", "codeq:abandon", "codeq:nack", "codeq:result", "codeq:subscribe"} {
				allowed[p] = struct{}{}
			}
		default:
		}
		if s.roleSvc != nil {
			if perms, err := s.roleSvc.ResolvePermissions(ctx, tenantID, []string{r}); err == nil {
				for _, p := range perms {
					allowed[p] = struct{}{}
				}
			}
		}
	}
	for _, sc := range scopes {
		if _, ok := allowed[sc]; !ok {
			return false
		}
	}
	return true
}

func normalizeList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func (s *userService) listTenantIDs(ctx context.Context, userID string) []string {
	if s.directoryAccess != nil && userID != "" {
		ids, exceeded, err := s.directoryAccess.ListEffectiveTenantIDs(ctx, userID, maximumMembershipsScanned)
		if err == nil && !exceeded {
			return withoutRetiredDefaultTenant(ids)
		}
		return nil
	}
	if s.membershipRepo == nil || userID == "" {
		return nil
	}
	ids, err := s.membershipRepo.ListTenantIDsByUser(ctx, userID)
	if err != nil {
		return nil
	}
	if len(ids) == 0 {
		return nil
	}
	ids = withoutRetiredDefaultTenant(ids)
	sort.Strings(ids)
	return ids
}

func (s *userService) resolveTenantID(ctx context.Context, u *domain.User) string {
	if u == nil {
		return ""
	}
	ids := s.listTenantIDs(ctx, u.Id)
	if len(ids) > 0 {
		return ids[0]
	}
	tenantID := derefString(u.CompanyId)
	if tenantID == domain.RetiredDefaultTenantID {
		return ""
	}
	return tenantID
}

func withoutRetiredDefaultTenant(ids []string) []string {
	active := ids[:0]
	for _, tenantID := range ids {
		if tenantID != domain.RetiredDefaultTenantID {
			active = append(active, tenantID)
		}
	}
	return active
}

func containsString(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func subset(items []string, allowed []string) bool {
	if len(items) == 0 {
		return true
	}
	allowedSet := map[string]struct{}{}
	for _, a := range allowed {
		if a == "" {
			continue
		}
		allowedSet[a] = struct{}{}
	}
	for _, item := range items {
		if item == "" {
			continue
		}
		if _, ok := allowedSet[item]; !ok {
			return false
		}
	}
	return true
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// UpdateUser allows authenticated users to change email and/or password.
func (s *userService) UpdateUser(ctx context.Context, req domain.UpdateReq) (*domain.UpdateResp, error) {
	_, u, err := s.validateCurrentIDToken(ctx, req.IdToken, s.issuerBaseURL, s.defaultAudience)
	if err != nil {
		return nil, err
	}
	if req.Email != "" {
		u.Email = req.Email
	}
	if req.Password != "" {
		if !passwordCredentialEligible(u) {
			return nil, domain.ErrInvalidArgument
		}
		if !validDirectoryPassword(req.Password) {
			return nil, domain.ErrInvalidArgument
		}
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if hashErr != nil {
			return nil, domain.ErrInvalidArgument
		}
		u.Password = string(hash)
		u.PasswordChangeRequired = false
		u.TokenVersion++
	}
	if e2 := s.repo.UpdateUser(ctx, u); e2 != nil {
		return nil, e2
	}
	return &domain.UpdateResp{
		LocalId: u.Id,
		Email:   u.Email,
	}, nil
}

// DeleteUser removes the authenticated user identified by the idToken.
func (s *userService) DeleteUser(ctx context.Context, req domain.DeleteReq) error {
	_, u, err := s.validateCurrentIDToken(ctx, req.IdToken, s.issuerBaseURL, s.defaultAudience)
	if err != nil {
		return err
	}
	// Tenant-local SAML principals are keyed by immutable subject, not email.
	// The legacy self-delete contract has only email semantics; rejecting it is
	// safer than deleting an unrelated global user with the same address.
	if u.AuthSource == domain.AuthSourceSAML {
		return domain.ErrInvalidArgument
	}
	return s.repo.DeleteByEmail(ctx, u.Email)
}

// SendOob generates a one-time code and stores payload metadata for subsequent resets.
func (s *userService) SendOob(ctx context.Context, req domain.SendOobReq) (*domain.SendOobResp, error) {
	reqType := strings.TrimSpace(strings.ToUpper(req.RequestType))
	switch reqType {
	case "PASSWORD_RESET", "EMAIL_SIGNIN":
	default:
		return nil, domain.ErrInvalidArgument
	}

	email := normalizeIdentityEmail(req.Email)
	if email == "" {
		return nil, domain.ErrInvalidArgument
	}
	limit := s.authenticationRateLimits.OOB
	allowed, limitErr := s.allowAuthenticationAttempt(ctx, authenticationBucketOOBEmail, email, limit.Requests, time.Duration(limit.WindowSeconds)*time.Second)
	if limitErr != nil {
		return nil, domain.ErrAuthenticationUnavailable
	}
	if !allowed {
		return nil, domain.ErrRateLimited
	}

	u, e := s.repo.FindByEmail(ctx, email)
	if e != nil || u == nil || u.Status != domain.UserStatusActive || !passwordCredentialEligible(u) {
		if reqType == "EMAIL_SIGNIN" {
			// Anti-enumeration: always return success for email sign-in requests.
			return &domain.SendOobResp{
				Kind:    "identitytoolkit#GetOobConfirmationCodeResponse",
				Email:   email,
				OobCode: uuid.NewString(),
			}, nil
		}
		return nil, domain.ErrNotFound
	}
	code := uuid.NewString()
	if err := s.repo.SaveOobCode(ctx, code, email, reqType); err != nil {
		return nil, err
	}
	return &domain.SendOobResp{
		Kind:    "identitytoolkit#GetOobConfirmationCodeResponse",
		Email:   email,
		OobCode: code,
	}, nil
}

func (s *userService) SendOobForTenant(ctx context.Context, tenantID string, req domain.SendOobReq) (*domain.SendOobTenantResp, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, domain.ErrInvalidTenant
	}

	reqType := strings.TrimSpace(strings.ToUpper(req.RequestType))
	switch reqType {
	case "PASSWORD_RESET", "EMAIL_SIGNIN":
	default:
		return nil, domain.ErrInvalidArgument
	}

	email := normalizeIdentityEmail(req.Email)
	if email == "" {
		return nil, domain.ErrInvalidArgument
	}
	limit := s.authenticationRateLimits.OOB
	allowed, limitErr := s.allowAuthenticationAttempt(ctx, authenticationBucketOOBEmail, email, limit.Requests, time.Duration(limit.WindowSeconds)*time.Second)
	if limitErr != nil {
		return nil, domain.ErrAuthenticationUnavailable
	}
	if !allowed {
		return nil, domain.ErrRateLimited
	}

	u, e := s.repo.FindByEmail(ctx, email)
	if e != nil {
		return nil, e
	}
	antiEnumerationResponse := func() (*domain.SendOobTenantResp, error) {
		return &domain.SendOobTenantResp{
			Kind:        "tikti#SendOobResponse",
			Email:       email,
			RequestType: reqType,
			ExpiresIn:   900,
			OobCode:     uuid.NewString(),
		}, nil
	}
	if u == nil {
		if reqType == "PASSWORD_RESET" {
			return nil, domain.ErrNotFound
		}
		// Identity V2 provisions users only through the audited global directory.
		// Preserve the public anti-enumeration response without persisting a user,
		// membership, assignment, or usable OOB code.
		return antiEnumerationResponse()
	}

	if u.Status != domain.UserStatusActive {
		if reqType == "PASSWORD_RESET" {
			return nil, domain.ErrNotFound
		}
		return antiEnumerationResponse()
	}
	if !passwordCredentialEligible(u) {
		if reqType == "PASSWORD_RESET" {
			return nil, domain.ErrNotFound
		}
		return antiEnumerationResponse()
	}

	// Every tenant-scoped OOB operation, including PASSWORD_RESET, must be
	// authorized by canonical effective access or the user's exact legacy
	// company. The latter remains a read-only migration fallback.
	// This check deliberately happens before the OOB code is generated or saved.
	if s.directoryAccess != nil {
		roles, _, accessErr := s.directoryAccess.GetEffectiveTenantRoles(ctx, u.Id, tenantID)
		if accessErr != nil {
			return nil, accessErr
		}
		if len(roles) == 0 && (u.CompanyId == nil || *u.CompanyId != tenantID) {
			if reqType == "EMAIL_SIGNIN" {
				return antiEnumerationResponse()
			}
			return nil, domain.ErrInvalidTenant
		}
	} else if s.membershipRepo != nil {
		membership, err := s.membershipRepo.Get(ctx, tenantID, u.Id)
		if err != nil {
			return nil, err
		}
		if membership == nil && (u.CompanyId == nil || *u.CompanyId != tenantID) {
			if reqType == "EMAIL_SIGNIN" {
				return antiEnumerationResponse()
			}
			return nil, domain.ErrInvalidTenant
		}
	} else if u.CompanyId == nil || *u.CompanyId != tenantID {
		if reqType == "EMAIL_SIGNIN" {
			return antiEnumerationResponse()
		}
		return nil, domain.ErrInvalidTenant
	}

	code := uuid.NewString()
	if err := s.repo.SaveOobCode(ctx, code, email, reqType); err != nil {
		return nil, err
	}

	return &domain.SendOobTenantResp{
		Kind:        "tikti#SendOobResponse",
		Email:       email,
		RequestType: reqType,
		ExpiresIn:   900,
		OobCode:     code,
	}, nil
}

// ResetPassword exchanges an OOB code for the stored email and updates the password hash.
func (s *userService) ResetPassword(ctx context.Context, req domain.ResetPwdReq) error {
	code := strings.TrimSpace(req.OobCode)
	newPassword := req.NewPassword
	if code == "" || !validDirectoryPassword(newPassword) {
		return domain.ErrInvalidArgument
	}

	email, e := s.repo.ConsumeOobCode(ctx, code, "PASSWORD_RESET")
	if e != nil {
		return domain.ErrInvalidOob
	}
	u, e2 := s.repo.FindByEmail(ctx, email)
	if e2 != nil || u == nil {
		return domain.ErrNotFound
	}
	if !passwordCredentialEligible(u) {
		return domain.ErrNotFound
	}
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if hashErr != nil {
		return domain.ErrInvalidArgument
	}
	u.Password = string(hash)
	u.PasswordChangeRequired = false
	u.TokenVersion++
	if e3 := s.repo.UpdateUser(ctx, u); e3 != nil {
		return e3
	}
	return nil
}

func passwordCredentialEligible(user *domain.User) bool {
	return user != nil && (user.AuthSource == "" || user.AuthSource == domain.AuthSourcePassword)
}

func (s *userService) issueIDToken(u *domain.User, amr []string) (string, int, error) {
	return s.issueIDTokenWithPlatformPrivilege(u, amr, "")
}

func (s *userService) issueIDTokenWithPlatformPrivilege(u *domain.User, amr []string, requestedPlatformPrivilege string) (string, int, error) {
	return s.issueIDTokenWithPlatformPrivilegeUntil(u, amr, requestedPlatformPrivilege, time.Time{})
}

func (s *userService) issueIDTokenWithPlatformPrivilegeUntil(u *domain.User, amr []string, requestedPlatformPrivilege string, absoluteExpiry time.Time) (string, int, error) {
	if u == nil {
		return "", 0, domain.ErrInvalidArgument
	}
	if u.Status != domain.UserStatusActive {
		return "", 0, domain.ErrInvalidCreds
	}
	if u.PasswordChangeRequired {
		return "", 0, domain.ErrPasswordChangeRequired
	}
	now := time.Now()
	expiresAt := now.Add(time.Hour)
	if !absoluteExpiry.IsZero() && absoluteExpiry.Before(expiresAt) {
		expiresAt = absoluteExpiry
	}
	nowUnix := now.Unix()
	expiresUnix := expiresAt.Unix()
	if expiresUnix <= nowUnix {
		return "", 0, domain.ErrInvalidArgument
	}
	platformPrivilege := issuablePlatformPrivilege(u, requestedPlatformPrivilege)
	claims := jwt.MapClaims{
		"sub":    u.Id,
		"userId": u.Id,
		"email":  u.Email,
		"role":   effectiveUserRole(u, platformPrivilege),
		"iss":    s.issuerBaseURL,
		"aud":    s.defaultAudience,
		"ver":    u.TokenVersion,
		"exp":    expiresUnix,
		"iat":    nowUnix,
	}
	if u.CompanyId != nil {
		if tid := strings.TrimSpace(*u.CompanyId); tid != "" && tid != domain.RetiredDefaultTenantID {
			claims["tid"] = tid
		}
	}
	if len(amr) > 0 {
		claims["amr"] = amr
	}
	if platformPrivilege != "" {
		claims[domain.PlatformPrivilegeClaim] = platformPrivilege
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", 0, err
	}
	return signed, int(expiresUnix - nowUnix), nil
}

func effectiveUserRole(user *domain.User, platformPrivilege ...string) domain.UserRole {
	privilege := ""
	if len(platformPrivilege) == 1 {
		privilege = platformPrivilege[0]
	}
	if user != nil && user.AuthSource == domain.AuthSourceSAML && user.Role == domain.RoleAdmin && privilege != domain.PlatformPrivilegeAdmin {
		return domain.RoleCompanyAdmin
	}
	if user == nil {
		return ""
	}
	return user.Role
}

func issuablePlatformPrivilege(user *domain.User, requested string) string {
	if user != nil && user.Status == domain.UserStatusActive && user.AuthSource == domain.AuthSourceSAML &&
		user.Role == domain.RoleAdmin && requested == domain.PlatformPrivilegeAdmin {
		return domain.PlatformPrivilegeAdmin
	}
	return ""
}

func validatedPlatformPrivilege(user *domain.User, claims jwt.MapClaims) string {
	if issuablePlatformPrivilege(user, claimStringValue(claims, domain.PlatformPrivilegeClaim)) == "" ||
		claimStringValue(claims, "role") != string(domain.RoleAdmin) || user.CompanyId == nil ||
		claimStringValue(claims, "tid") != strings.TrimSpace(*user.CompanyId) {
		return ""
	}
	version, valid := tokenVersion(claims)
	if !valid || version != user.TokenVersion {
		return ""
	}
	return domain.PlatformPrivilegeAdmin
}

// IssueIDTokenWithAMR is the exported wrapper around issueIDToken that
// accepts an explicit AMR slice.  It satisfies the saml.IDTokenIssuer
// interface so the SAML SessionBridge can reuse the existing HS256 issuer.
func (s *userService) IssueIDTokenWithAMR(u *domain.User, amr []string, platformPrivilege string) (string, int, error) {
	return s.issueIDTokenWithPlatformPrivilege(u, amr, platformPrivilege)
}

// IssueIDTokenWithAMRUntil issues a SAML-backed local session whose absolute
// expiry can never exceed the assertion/session NotOnOrAfter boundary.
func (s *userService) IssueIDTokenWithAMRUntil(u *domain.User, amr []string, platformPrivilege string, notOnOrAfter time.Time) (string, int, error) {
	if notOnOrAfter.IsZero() {
		return "", 0, domain.ErrInvalidArgument
	}
	return s.issueIDTokenWithPlatformPrivilegeUntil(u, amr, platformPrivilege, notOnOrAfter)
}
