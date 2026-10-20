package services

import (
	"context"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const managedLogsPlatformReadScope = "code-admin:logs:platform:read"

// managedLogsPlatformAuthority checks an existing revocable platform identity.
// A tenant role, a similarly named ADMIN assignment or an arbitrary audience
// default cannot introduce this new operations permission.
func (s *userService) managedLogsPlatformAuthority(ctx context.Context, user *domain.User, claims jwt.MapClaims) bool {
	if user == nil || user.Status != domain.UserStatusActive || user.CompanyId == nil || !s.currentPlatformAuthorityValid(user, claims) {
		return false
	}
	if user.AuthSource == domain.AuthSourceSAML {
		return s.platformAuthorityConfigured && trustedFederatedPlatformPrincipal(user, strings.TrimSpace(*user.CompanyId), validatedPlatformPrivilege(user, claims))
	}
	if user.AuthSource != domain.AuthSourcePassword || user.Role != domain.RoleAdmin || s.directoryAccess == nil {
		return false
	}
	assignment, err := s.directoryAccess.GetAccessAssignment(ctx, domain.MasterTenantID, domain.AccessPrincipalUser, user.Id)
	return err == nil && assignment != nil && assignment.TenantID == domain.MasterTenantID && assignment.PrincipalType == domain.AccessPrincipalUser && assignment.PrincipalID == user.Id && slices.Equal(assignment.Roles, []string{string(domain.RoleAdmin)})
}

func (s *userService) managedLogsPlatformIssuance(ctx context.Context, user *domain.User, claims jwt.MapClaims, request domain.TokenExchangeReq, tenant string) bool {
	if request.Audience != domain.CodeAdminAudienceClientID || !slices.Contains(request.Scopes, managedLogsPlatformReadScope) || s.clientSvc == nil || !s.managedLogsPlatformAuthority(ctx, user, claims) {
		return false
	}
	client, err := s.clientSvc.GetClient(ctx, tenant, request.Audience)
	return err == nil && client != nil && client.Id == request.Audience && client.TenantId == tenant && client.Status == domain.ClientStatusActive && slices.Contains(client.DefaultScopes, managedLogsPlatformReadScope)
}
