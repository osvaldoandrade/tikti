package services

import (
	"context"
	"slices"
	"strings"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// DirectoryDeletionAuthority binds deletion to the current administrative bearer.
type DirectoryDeletionAuthority interface {
	CurrentDirectoryDeletionActor(context.Context, string, string, string) (domain.DirectoryDeletionActor, error)
}

func (s *userService) CurrentDirectoryDeletionActor(ctx context.Context, token, issuer, audience string) (domain.DirectoryDeletionActor, error) {
	claims, err := s.ValidateAccessToken(ctx, token, issuer, audience)
	if err != nil {
		return domain.DirectoryDeletionActor{}, domain.ErrDirectoryDeletionDenied
	}
	subject, email := claimStringValue(claims, "sub"), claimStringValue(claims, "email")
	if subject == "" || claimStringValue(claims, "role") != string(domain.RoleAdmin) ||
		claimStringValue(claims, domain.PlatformPrivilegeClaim) != domain.PlatformPrivilegeAdmin ||
		!slices.Contains(strings.Fields(claimStringValue(claims, "scope")), domain.PlatformTenantAdminScope) {
		return domain.DirectoryDeletionActor{}, domain.ErrDirectoryDeletionDenied
	}
	user, err := s.resolveCurrentTokenUser(ctx, subject, email)
	version, valid := tokenVersion(claims)
	if err != nil || user == nil || !valid || user.Id != subject || user.Status != domain.UserStatusActive ||
		user.Role != domain.RoleAdmin || user.PasswordChangeRequired || user.TokenVersion != version ||
		user.Revision < 0 || !s.currentPlatformAuthorityValid(user, claims) {
		return domain.DirectoryDeletionActor{}, domain.ErrDirectoryDeletionDenied
	}
	recovered := user.AuthSource == domain.AuthSourcePassword && user.CompanyId != nil &&
		*user.CompanyId != domain.MasterTenantID && claimStringValue(claims, "tid") == domain.MasterTenantID &&
		claimStringValue(claims, "principal_tid") == domain.MasterTenantID
	if recovered && !s.recoveredMasterPlatformAdministrator(ctx, user) {
		return domain.DirectoryDeletionActor{}, domain.ErrDirectoryDeletionDenied
	}
	return domain.DirectoryDeletionActor{UserID: user.Id, TokenVersion: version, Revision: user.Revision, RecoveredMaster: recovered}, nil
}
