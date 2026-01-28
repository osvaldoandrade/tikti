package services

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type MembershipService interface {
	Create(ctx context.Context, tenantID string, req domain.MembershipCreateReq) (*domain.MembershipResp, error)
	Remove(ctx context.Context, tenantID string, req domain.MembershipRemoveReq) (*domain.MembershipRemoveResp, error)
	ListTenantIDsByUser(ctx context.Context, userID string) ([]string, error)
}

type membershipService struct {
	userRepo repository.UserRepository
	repo     repository.MembershipRepository
}

func NewMembershipService(userRepo repository.UserRepository, repo repository.MembershipRepository) MembershipService {
	return &membershipService{userRepo: userRepo, repo: repo}
}

func (s *membershipService) Create(ctx context.Context, tenantID string, req domain.MembershipCreateReq) (*domain.MembershipResp, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, domain.ErrInvalidTenant
	}
	if strings.TrimSpace(req.Email) == "" {
		return nil, domain.ErrInvalidArgument
	}
	u, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, domain.ErrNotFound
	}
	m := &domain.Membership{
		Id:        uuid.NewString(),
		TenantId:  tenantID,
		UserId:    u.Id,
		Roles:     req.Roles,
		CreatedAt: time.Now(),
	}
	if err := s.repo.Create(ctx, m); err != nil {
		return nil, err
	}
	if u.CompanyId == nil {
		u.CompanyId = &tenantID
		_ = s.userRepo.UpdateUser(ctx, u)
	}
	return &domain.MembershipResp{
		Id:        m.Id,
		TenantId:  m.TenantId,
		UserId:    m.UserId,
		Email:     u.Email,
		Roles:     m.Roles,
		CreatedAt: m.CreatedAt,
	}, nil
}

func (s *membershipService) Remove(ctx context.Context, tenantID string, req domain.MembershipRemoveReq) (*domain.MembershipRemoveResp, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, domain.ErrInvalidTenant
	}
	if strings.TrimSpace(req.Email) == "" {
		return nil, domain.ErrInvalidArgument
	}
	u, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, domain.ErrNotFound
	}
	if err := s.repo.Delete(ctx, tenantID, u.Id); err != nil {
		return nil, err
	}
	return &domain.MembershipRemoveResp{
		TenantId:  tenantID,
		UserId:    u.Id,
		Email:     u.Email,
		RemovedAt: time.Now(),
	}, nil
}

func (s *membershipService) ListTenantIDsByUser(ctx context.Context, userID string) ([]string, error) {
	return s.repo.ListTenantIDsByUser(ctx, userID)
}
