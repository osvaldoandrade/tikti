package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type TenantService interface {
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

func (s *tenantService) CreateWithID(
	ctx context.Context,
	tenantID string,
	req domain.TenantCreateReq,
) (*domain.TenantResp, bool, error) {
	req.Name = strings.TrimSpace(req.Name)
	if !validDNSLabel(tenantID) || !validTenantName(req.Name) || req.Slug != tenantID ||
		tenantID == domain.MasterTenantID && req.Name != domain.MasterTenantName ||
		tenantID != domain.MasterTenantID && strings.EqualFold(req.Name, domain.MasterTenantName) {
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
	if tenant.Id == domain.MasterTenantID && tenant.Slug != domain.MasterTenantID ||
		tenant.Id != domain.MasterTenantID && strings.EqualFold(strings.TrimSpace(tenant.Name), domain.MasterTenantName) {
		return nil, domain.ErrTenantInvariant
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
	tenantType := domain.TenantTypeWorkload
	name := tenant.Name
	if tenant.Id == domain.MasterTenantID {
		tenantType = domain.TenantTypeMaster
		name = domain.MasterTenantName
	}
	return &domain.TenantResp{
		Id: tenant.Id, Slug: tenant.Slug, Name: name,
		Status: tenant.Status, CreatedAt: tenant.CreatedAt, TenantType: tenantType,
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
		items = append(items, *tenantResponse(&tenant))
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
	return tenantResponse(t), nil
}
