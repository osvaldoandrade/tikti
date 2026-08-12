package services

import (
	"context"
	"errors"
	"slices"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

var errMembershipV2WriteUnavailable = errors.New("membership v2 write unavailable")

// MembershipV2WriteService validates exact dependencies before the immutable write.
type MembershipV2WriteService interface {
	Ensure(ctx context.Context, tenantID, userID string, roles []string) (*domain.Membership, bool, error)
}

type membershipV2WriteService struct {
	tenants     repository.ExactTenantRepository
	users       repository.ExactUserRepository
	roles       repository.ExactRoleBatchRepository
	memberships repository.MembershipV2Repository
}

func NewMembershipV2WriteService(tenants repository.ExactTenantRepository, users repository.ExactUserRepository, roles repository.ExactRoleBatchRepository, memberships repository.MembershipV2Repository) MembershipV2WriteService {
	return &membershipV2WriteService{tenants: tenants, users: users, roles: roles, memberships: memberships}
}

func (s *membershipV2WriteService) Ensure(ctx context.Context, tenantID, userID string, roles []string) (*domain.Membership, bool, error) {
	if !validRoleTenantID(tenantID) {
		return nil, false, domain.ErrInvalidTenant
	}
	if !validMembershipV2WriteUser(userID) || !validMembershipV2WriteRoles(roles) {
		return nil, false, domain.ErrInvalidArgument
	}
	if s == nil || s.tenants == nil || s.users == nil || s.roles == nil || s.memberships == nil {
		return nil, false, errMembershipV2WriteUnavailable
	}
	tenant, err := s.tenants.GetExact(ctx, tenantID)
	if err != nil {
		return nil, false, membershipV2DependencyError(err)
	}
	if tenant == nil {
		return nil, false, domain.ErrMembershipDependencyNotFound
	}
	if tenant.Id != tenantID || tenant.Status != domain.TenantStatusActive {
		if tenant.Id == tenantID && tenant.Status == domain.TenantStatusDisabled {
			return nil, false, domain.ErrMembershipDependencyInactive
		}
		return nil, false, errMembershipV2WriteUnavailable
	}
	user, err := s.users.GetExact(ctx, userID)
	if err != nil {
		return nil, false, membershipV2DependencyError(err)
	}
	if user == nil {
		return nil, false, domain.ErrMembershipDependencyNotFound
	}
	if user.Id != userID || user.Status != domain.UserStatusActive {
		if user.Id == userID && (user.Status == domain.UserStatusInactive || user.Status == domain.UserStatusSuspended) {
			return nil, false, domain.ErrMembershipDependencyInactive
		}
		return nil, false, errMembershipV2WriteUnavailable
	}
	definitions, err := s.roles.GetManyExact(ctx, tenantID, roles)
	if err != nil {
		return nil, false, membershipV2DependencyError(err)
	}
	if len(definitions) != len(roles) {
		return nil, false, errMembershipV2WriteUnavailable
	}
	for index, definition := range definitions {
		if definition == nil {
			return nil, false, domain.ErrMembershipDependencyNotFound
		}
		if !exactRoleDefinition(tenantID, roles[index], definition) {
			return nil, false, errMembershipV2WriteUnavailable
		}
	}
	result, created, err := s.memberships.Ensure(ctx, tenantID, userID, roles)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidTenant) || errors.Is(err, domain.ErrInvalidArgument) ||
			errors.Is(err, domain.ErrMembershipConflict) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, false, err
		}
		return nil, false, errMembershipV2WriteUnavailable
	}
	if result == nil || result.Id != repository.ExpectedMembershipV2ID(tenantID, userID) || result.TenantId != tenantID || result.UserId != userID || result.CreatedAt.IsZero() || !slices.Equal(result.Roles, roles) {
		return nil, false, errMembershipV2WriteUnavailable
	}
	return result, created, nil
}

func validMembershipV2WriteUser(value string) bool {
	if value == "." || value == ".." || len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if !asciiAlphaNumeric(character) && character != '.' && character != '_' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func validMembershipV2WriteRoles(values []string) bool {
	if len(values) < 1 || len(values) > 100 {
		return false
	}
	for index, value := range values {
		if !validRoleName(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func membershipV2DependencyError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errMembershipV2WriteUnavailable
}
