package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/tenantname"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type TenantService interface {
	CreateWithID(ctx context.Context, tenantID string, req domain.TenantCreateReq) (*domain.TenantResp, bool, error)
	Get(ctx context.Context, tenantID string) (*domain.TenantResp, error)
	List(ctx context.Context, offset uint64, pageSize int64) (*domain.TenantsPage, error)
	IsTenantActive(ctx context.Context, tenantID string) (bool, error)
}

// IsTenantActive is the authoritative runtime gate used by browser-session
// entry points as well as access-token issuance. Missing and disabled tenants
// are both inactive; malformed persisted data fails closed as an invariant
// error.
func (s *tenantService) IsTenantActive(ctx context.Context, tenantID string) (bool, error) {
	if !validDNSLabel(tenantID) {
		return false, domain.ErrInvalidArgument
	}
	if tenantID == domain.RetiredDefaultTenantID {
		return false, nil
	}
	tenant, err := s.repo.Get(ctx, tenantID)
	if err != nil {
		return false, err
	}
	if tenant == nil {
		return false, nil
	}
	if tenant.Id != tenantID || !validStoredTenant(tenant) {
		return false, domain.ErrTenantInvariant
	}
	return tenant.Status == domain.TenantStatusActive, nil
}

type tenantService struct {
	repo repository.TenantRepository
}

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)

func NewTenantService(repo repository.TenantRepository) TenantService {
	return &tenantService{repo: repo}
}

func (s *tenantService) Retire(ctx context.Context, tenantID string) error {
	if !validDNSLabel(tenantID) || tenantID == domain.MasterTenantID || tenantID == domain.RetiredDefaultTenantID {
		return domain.ErrInvalidTenant
	}
	repo, ok := s.repo.(interface {
		Retire(context.Context, string) error
	})
	if !ok {
		return domain.ErrTenantInvariant
	}
	return repo.Retire(ctx, tenantID)
}

func (s *tenantService) CreateWithID(
	ctx context.Context,
	tenantID string,
	req domain.TenantCreateReq,
) (*domain.TenantResp, bool, error) {
	req.Name = tenantname.Normalize(req.Name)
	if !validDNSLabel(tenantID) || !validTenantName(req.Name) || req.Slug != tenantID ||
		tenantID == domain.RetiredDefaultTenantID ||
		tenantID == domain.MasterTenantID && req.Name != domain.MasterTenantName ||
		tenantID != domain.MasterTenantID && tenantname.ReservedMaster(req.Name) {
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
	if tenantID == domain.RetiredDefaultTenantID {
		return nil, domain.ErrNotFound
	}
	tenant, err := s.repo.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, domain.ErrNotFound
	}
	if !validStoredTenant(tenant) {
		return nil, domain.ErrTenantInvariant
	}
	return tenantResponse(tenant), nil
}

func validDNSLabel(value string) bool {
	return len(value) >= 1 && len(value) <= 63 && dnsLabelPattern.MatchString(value)
}

func validTenantName(value string) bool {
	return tenantname.Valid(value)
}

func validStoredTenant(tenant *domain.Tenant) bool {
	return tenant != nil && tenant.Id != domain.RetiredDefaultTenantID && validDNSLabel(tenant.Id) && tenant.Slug == tenant.Id && tenantname.Valid(tenant.Name) &&
		(tenant.Id == domain.MasterTenantID || !tenantname.ReservedMaster(tenant.Name))
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
		if !validStoredTenant(&tenant) {
			return nil, domain.ErrTenantInvariant
		}
		items = append(items, *tenantResponse(&tenant))
	}
	return &domain.TenantsPage{Tenants: items, NextPageToken: next}, nil
}
