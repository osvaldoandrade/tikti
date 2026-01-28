package services

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type TenantService interface {
	Create(ctx context.Context, req domain.TenantCreateReq) (*domain.TenantResp, error)
	Get(ctx context.Context, tenantID string) (*domain.TenantResp, error)
	EnsureDefault(ctx context.Context) (*domain.TenantResp, error)
}

type tenantService struct {
	repo repository.TenantRepository
}

func NewTenantService(repo repository.TenantRepository) TenantService {
	return &tenantService{repo: repo}
}

func (s *tenantService) Create(ctx context.Context, req domain.TenantCreateReq) (*domain.TenantResp, error) {
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Slug) == "" {
		return nil, domain.ErrInvalidArgument
	}
	tenant := &domain.Tenant{
		Id:     uuid.NewString(),
		Name:   req.Name,
		Slug:   req.Slug,
		Status: domain.TenantStatusActive,
	}
	if err := s.repo.Create(ctx, tenant); err != nil {
		return nil, err
	}
	return &domain.TenantResp{
		Id:        tenant.Id,
		Slug:      tenant.Slug,
		Name:      tenant.Name,
		Status:    tenant.Status,
		CreatedAt: tenant.CreatedAt,
	}, nil
}

func (s *tenantService) Get(ctx context.Context, tenantID string) (*domain.TenantResp, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, domain.ErrInvalidArgument
	}
	tenant, err := s.repo.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, domain.ErrNotFound
	}
	return &domain.TenantResp{
		Id:        tenant.Id,
		Slug:      tenant.Slug,
		Name:      tenant.Name,
		Status:    tenant.Status,
		CreatedAt: tenant.CreatedAt,
	}, nil
}

func (s *tenantService) EnsureDefault(ctx context.Context) (*domain.TenantResp, error) {
	t, err := s.repo.EnsureDefault(ctx)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, domain.ErrNotFound
	}
	return &domain.TenantResp{
		Id:        t.Id,
		Slug:      t.Slug,
		Name:      t.Name,
		Status:    t.Status,
		CreatedAt: t.CreatedAt,
	}, nil
}
