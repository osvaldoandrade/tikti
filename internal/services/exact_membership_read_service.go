package services

import (
	"context"
	"errors"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// ExactMembershipReadService enforces the active-tenant boundary before using
// the additive, fail-closed exact membership repositories.
type ExactMembershipReadService interface {
	Get(ctx context.Context, tenantID, userID string) (*domain.MembershipIdentity, error)
	List(ctx context.Context, tenantID, pageToken string, pageSize int) (*domain.MembershipIdentitiesPage, error)
}

type exactMembershipReadService struct {
	tenants repository.ExactTenantRepository
	exact   repository.ExactMembershipReader
	list    repository.ExactMembershipListReader
}

var errExactMembershipReadUnavailable = errors.New("exact membership read unavailable")

func NewExactMembershipReadService(tenants repository.ExactTenantRepository, exact repository.ExactMembershipReader, list repository.ExactMembershipListReader) ExactMembershipReadService {
	return &exactMembershipReadService{tenants: tenants, exact: exact, list: list}
}

func (s *exactMembershipReadService) Get(ctx context.Context, tenantID, userID string) (*domain.MembershipIdentity, error) {
	if err := s.requireActiveTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	result, err := s.exact.GetExact(ctx, tenantID, userID)
	if err != nil {
		return nil, exactMembershipReadError(err)
	}
	if result == nil {
		return nil, domain.ErrMembershipNotFound
	}
	return result, nil
}

func (s *exactMembershipReadService) List(ctx context.Context, tenantID, pageToken string, pageSize int) (*domain.MembershipIdentitiesPage, error) {
	if err := s.requireActiveTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	result, err := s.list.ListExact(ctx, tenantID, pageToken, pageSize)
	if err != nil {
		return nil, exactMembershipReadError(err)
	}
	if result == nil {
		return nil, errExactMembershipReadUnavailable
	}
	return result, nil
}

func (s *exactMembershipReadService) requireActiveTenant(ctx context.Context, tenantID string) error {
	if s == nil || s.tenants == nil || s.exact == nil || s.list == nil {
		return errExactMembershipReadUnavailable
	}
	tenant, err := s.tenants.GetExact(ctx, tenantID)
	if errors.Is(err, domain.ErrInvalidTenant) {
		return err
	}
	if err != nil || tenant == nil || tenant.Id != tenantID || tenant.Status != domain.TenantStatusActive {
		return errExactMembershipReadUnavailable
	}
	return nil
}

func exactMembershipReadError(err error) error {
	if errors.Is(err, domain.ErrInvalidTenant) || errors.Is(err, domain.ErrInvalidArgument) {
		return err
	}
	if errors.Is(err, repository.ErrExactMembershipListStaleCursor) {
		return domain.ErrMembershipPageStale
	}
	return errExactMembershipReadUnavailable
}
