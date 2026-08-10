package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type TenantService interface {
	Create(ctx context.Context, req domain.TenantCreateReq) (*domain.TenantResp, error)
	CreateWithID(ctx context.Context, tenantID string, req domain.TenantCreateReq) (*domain.TenantResp, bool, error)
	Get(ctx context.Context, tenantID string) (*domain.TenantResp, error)
	List(ctx context.Context, offset uint64, pageSize int64) (*domain.TenantsPage, error)
	EnsureDefault(ctx context.Context) (*domain.TenantResp, error)
}

type tenantService struct {
	repo repository.TenantRepository
}

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)

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
	return tenantResponse(tenant), nil
}

func (s *tenantService) CreateWithID(
	ctx context.Context,
	tenantID string,
	req domain.TenantCreateReq,
) (*domain.TenantResp, bool, error) {
	req.Name = strings.TrimSpace(req.Name)
	if !validDNSLabel(tenantID) || !validTenantName(req.Name) || req.Slug != tenantID {
		return nil, false, domain.ErrInvalidArgument
	}
	proposed := &domain.Tenant{
		Id: tenantID, Name: req.Name, Slug: req.Slug, Status: domain.TenantStatusActive,
	}
	existing, created, err := s.repo.CreateIfAbsent(ctx, proposed)
	if err != nil {
		return nil, false, fmt.Errorf("create tenant %q: %w", tenantID, err)
	}
	if existing == nil {
		return nil, false, fmt.Errorf("create tenant %q: stored tenant missing", tenantID)
	}
	if existing.Name != proposed.Name || existing.Slug != proposed.Slug {
		return nil, false, domain.ErrTenantConflict
	}
	return tenantResponse(existing), created, nil
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
	return tenantResponse(tenant), nil
}

func validDNSLabel(value string) bool {
	return len(value) >= 1 && len(value) <= 63 && dnsLabelPattern.MatchString(value)
}

func validTenantName(value string) bool {
	length := utf8.RuneCountInString(value)
	return length >= 1 && length <= 128
}

func tenantResponse(tenant *domain.Tenant) *domain.TenantResp {
	return &domain.TenantResp{
		Id: tenant.Id, Slug: tenant.Slug, Name: tenant.Name,
		Status: tenant.Status, CreatedAt: tenant.CreatedAt,
	}
}

func (s *tenantService) List(ctx context.Context, offset uint64, pageSize int64) (*domain.TenantsPage, error) {
	if pageSize < 1 || pageSize > 200 {
		return nil, domain.ErrInvalidArgument
	}
	tenants, next, err := s.repo.List(ctx, offset, pageSize)
	if err != nil {
		return nil, err
	}
	items := make([]domain.TenantResp, 0, len(tenants))
	for _, tenant := range tenants {
		items = append(items, domain.TenantResp{
			Id: tenant.Id, Slug: tenant.Slug, Name: tenant.Name,
			Status: tenant.Status, CreatedAt: tenant.CreatedAt,
		})
	}
	return &domain.TenantsPage{Tenants: items, NextPageToken: next}, nil
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
