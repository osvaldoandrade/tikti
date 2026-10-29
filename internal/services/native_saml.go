package services

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/osvaldoandrade/tikti/internal/nativeauth"
	"github.com/osvaldoandrade/tikti/internal/nativepolicy"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func WithNativeSAMLClients(clients *nativepolicy.Registry) UserServiceOption {
	return func(service *userService) { service.nativeClients = clients }
}

func nativeScopesEqual(actual, expected []string) bool {
	copy := slices.Clone(actual)
	slices.Sort(copy)
	return slices.Equal(copy, expected)
}

func (s *userService) registeredNativeClient(client nativepolicy.Client) bool {
	registered, exists := s.nativeClients.Get(client.ID)
	expected, err := registered.Fingerprint()
	actual, inputErr := client.Fingerprint()
	return exists && err == nil && inputErr == nil && expected == actual
}

func (s *userService) BrowserIdentity(ctx context.Context, session string, client nativepolicy.Client) (nativeauth.Identity, error) {
	claims, user, err := s.validateCurrentIDToken(ctx, session, s.issuerBaseURL, s.defaultAudience)
	if err != nil {
		return nativeauth.Identity{}, nativeauth.ErrNoSession
	}
	methods, valid := canonicalAuthenticationMethods(claims)
	deadline, expiryErr := claims.GetExpirationTime()
	if !valid || !slices.Equal(methods, []string{"saml"}) || expiryErr != nil || deadline == nil ||
		deadline.Unix() <= time.Now().Unix() || claimStringValue(claims, "sub") != user.Id {
		return nativeauth.Identity{}, nativeauth.ErrNoSession
	}
	identity, _, err := s.currentNativeIdentity(ctx, user, client)
	if err != nil {
		return nativeauth.Identity{}, err
	}
	identity.SessionExpiresAt = deadline.Unix()
	return identity, nil
}

func (s *userService) currentNativeIdentity(ctx context.Context, user *domain.User, client nativepolicy.Client) (nativeauth.Identity, []string, error) {
	deny := nativeauth.ErrAccessDenied
	if !s.registeredNativeClient(client) || user == nil || user.Id == "" || user.Email == "" ||
		user.AuthSource != domain.AuthSourceSAML || user.CompanyId == nil || *user.CompanyId != client.IdentityTenantID ||
		user.Status != domain.UserStatusActive || user.PasswordChangeRequired || !s.currentPlatformAuthorityValid(user, jwt.MapClaims{}) ||
		s.tenantRepo == nil || s.clientSvc == nil || s.directoryAccess == nil || s.roleSvc == nil {
		return nativeauth.Identity{}, nil, deny
	}
	var tenantName string
	for _, id := range []string{client.IdentityTenantID, client.TenantID} {
		tenant, err := s.tenantRepo.Get(ctx, id)
		if err != nil {
			return nativeauth.Identity{}, nil, nativeauth.ErrUnavailable
		}
		if tenant == nil || tenant.Id != id || tenant.Status != domain.TenantStatusActive {
			return nativeauth.Identity{}, nil, deny
		}
		if id == client.TenantID {
			tenantName = tenant.Name
		}
	}
	held, _, err := s.directoryAccess.GetEffectiveTenantRoles(ctx, user.Id, client.TenantID)
	if err != nil {
		return nativeauth.Identity{}, nil, nativeauth.ErrUnavailable
	}
	roles := []string{}
	for _, expected := range append([]nativepolicy.Role{client.BaseRole}, client.AdditionalRoles...) {
		if !slices.Contains(held, expected.Name) {
			continue
		}
		definition, readErr := s.roleSvc.GetByName(ctx, client.TenantID, expected.Name)
		if readErr != nil || definition == nil || definition.Name != expected.Name || !nativeScopesEqual(definition.Permissions, expected.Scopes) {
			return nativeauth.Identity{}, nil, deny
		}
		roles = append(roles, expected.Name)
	}
	slices.Sort(roles)
	scopes, err := client.ScopesForRoles(roles)
	if err != nil {
		return nativeauth.Identity{}, nil, deny
	}
	audience, err := s.clientSvc.GetClient(ctx, client.TenantID, client.Audience)
	if err != nil {
		return nativeauth.Identity{}, nil, nativeauth.ErrUnavailable
	}
	if audience == nil || audience.Id != client.Audience || audience.TenantId != client.TenantID || audience.Status != domain.ClientStatusActive ||
		!subset(scopes, audience.DefaultScopes) {
		return nativeauth.Identity{}, nil, deny
	}
	return nativeauth.Identity{Subject: user.Id, Email: user.Email, IdentityTenantID: *user.CompanyId,
		TenantName: tenantName, TokenVersion: int64(user.TokenVersion), Scopes: scopes}, roles, nil
}

func (s *userService) IssueNativeToken(ctx context.Context, client nativepolicy.Client, grant nativeauth.Grant) (nativeauth.Token, error) {
	byID, ok := s.repo.(repository.UserIDRepository)
	if !ok {
		return nativeauth.Token{}, nativeauth.ErrUnavailable
	}
	user, err := byID.FindByID(ctx, grant.Subject)
	if err != nil {
		return nativeauth.Token{}, nativeauth.ErrUnavailable
	}
	identity, roles, err := s.currentNativeIdentity(ctx, user, client)
	if err != nil {
		return nativeauth.Token{}, err
	}
	policy, _ := client.Fingerprint()
	if grant.ClientID != client.ID || grant.ClientFingerprint != policy || client.ValidateRedirect(grant.RedirectURI) != nil ||
		identity.Subject != grant.Subject || identity.TokenVersion != grant.TokenVersion || identity.IdentityTenantID != grant.IdentityTenantID ||
		identity.Fingerprint() != grant.IdentityFingerprint || len(grant.ApprovedScopes) == 0 ||
		!subset(grant.ApprovedScopes, identity.Scopes) || !subset(client.RequiredScopes, grant.ApprovedScopes) {
		return nativeauth.Token{}, nativeauth.ErrInvalidGrant
	}
	now := time.Now().Unix()
	expires := min(now+int64(client.TTLSeconds), grant.SessionExpiresAt)
	if expires <= now || grant.ExpiresAt <= now {
		return nativeauth.Token{}, nativeauth.ErrInvalidGrant
	}
	key, err := s.getRSAPrivateKey()
	if err != nil {
		return nativeauth.Token{}, nativeauth.ErrUnavailable
	}
	scopes := slices.Clone(grant.ApprovedScopes)
	slices.Sort(scopes)
	// Role claims obey the approved permission ceiling as well. A role added
	// after consent must not convey capabilities absent from the token scopes.
	approvedRoles := []string{}
	for _, role := range append([]nativepolicy.Role{client.BaseRole}, client.AdditionalRoles...) {
		if slices.Contains(roles, role.Name) && subset(role.Scopes, scopes) {
			approvedRoles = append(approvedRoles, role.Name)
		}
	}
	slices.Sort(approvedRoles)
	claims := jwt.MapClaims{
		"iss": s.issuerBaseURL, "aud": client.Audience, "sub": identity.Subject, "email": identity.Email,
		"tid": client.TenantID, "principal_tid": client.IdentityTenantID, "role": string(domain.RoleCompanyEmployee),
		"roles": approvedRoles, "scope": strings.Join(scopes, " "), "amr": []string{"saml"}, "ver": identity.TokenVersion,
		"iat": now, "exp": expires, "jti": uuid.NewString(), "native_client_id": client.ID, "native_policy": policy,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.jwksKeyID
	signed, err := token.SignedString(key)
	if err != nil {
		return nativeauth.Token{}, nativeauth.ErrUnavailable
	}
	return nativeauth.Token{AccessToken: signed, TokenType: "Bearer", ExpiresIn: int(expires - now), Scope: strings.Join(scopes, " "), Email: identity.Email}, nil
}

func (s *userService) validateNativeAccessToken(ctx context.Context, user *domain.User, claims jwt.MapClaims) error {
	client, exists := s.nativeClients.Get(claimStringValue(claims, "native_client_id"))
	policy, err := client.Fingerprint()
	methods, valid := canonicalAuthenticationMethods(claims)
	if !exists || err != nil || policy != claimStringValue(claims, "native_policy") ||
		claimStringValue(claims, "tid") != client.TenantID || !tokenHasAudience(claims, client.Audience) ||
		claimStringValue(claims, "principal_tid") != client.IdentityTenantID || claimStringValue(claims, "role") != string(domain.RoleCompanyEmployee) ||
		claims[domain.PlatformPrivilegeClaim] != nil || claims[platformAuthorityOriginClaim] != nil ||
		!valid || !slices.Equal(methods, []string{"saml"}) {
		return domain.ErrInvalidToken
	}
	identity, currentRoles, err := s.currentNativeIdentity(ctx, user, client)
	scopes := strings.Fields(claimStringValue(claims, "scope"))
	if err != nil || len(scopes) == 0 || !subset(scopes, identity.Scopes) || !subset(client.RequiredScopes, scopes) {
		return domain.ErrInvalidToken
	}
	signedRoles, validRoles := canonicalAccessTokenRoles(claims["roles"])
	if !validRoles || !slices.Contains(signedRoles, client.BaseRole.Name) || !subset(signedRoles, currentRoles) {
		return domain.ErrInvalidToken
	}
	known := map[string][]string{}
	for _, role := range append([]nativepolicy.Role{client.BaseRole}, client.AdditionalRoles...) {
		known[role.Name] = role.Scopes
	}
	for _, role := range signedRoles {
		permissions, exists := known[role]
		if !exists || !subset(permissions, scopes) {
			return domain.ErrInvalidToken
		}
	}
	return nil
}
