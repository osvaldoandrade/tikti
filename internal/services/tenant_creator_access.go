package services

import (
	"context"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// CreatorAccess observes the same current authority used by token exchange.
// A trusted MASTER federated administrator already has platform access and
// must not be given an artificial cross-tenant SAML membership.
func (s *identityDirectoryService) CreatorAccess(ctx context.Context, tenantID, subject, privilege string) (string, error) {
	if s == nil || s.tenants == nil || privilege != domain.PlatformPrivilegeAdmin {
		return "", domain.ErrInvalidTenant
	}
	tenant, err := s.tenants.GetExact(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if tenant == nil {
		return "", domain.ErrNotFound
	}
	if tenant.Status != domain.TenantStatusActive {
		return "", domain.ErrMembershipDependencyInactive
	}
	users, ok := s.users.(repository.UserIDRepository)
	if !ok {
		return "", domain.ErrDirectoryInvariant
	}
	user, err := users.FindByID(ctx, subject)
	if err != nil {
		return "", err
	}
	if user == nil || user.Id != subject || user.Status != domain.UserStatusActive || user.Role != domain.RoleAdmin {
		return "", domain.ErrInvalidTenant
	}
	if trustedFederatedPlatformPrincipal(user, domain.MasterTenantID, privilege) {
		return "PLATFORM", nil
	}
	if user.AuthSource == domain.AuthSourceSAML && (user.CompanyId == nil || *user.CompanyId != tenantID) {
		return "", domain.ErrInvalidTenant
	}
	return "MEMBERSHIP", nil
}
