package services

import (
	"context"
	"sort"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type RoleService interface {
	Create(ctx context.Context, tenantID string, req domain.RoleCreateReq) (*domain.RoleResp, error)
	List(ctx context.Context, tenantID string) ([]*domain.RoleResp, error)
	ResolvePermissions(ctx context.Context, tenantID string, roles []string) ([]string, error)
}

type roleService struct {
	repo repository.RoleRepository
}

func NewRoleService(repo repository.RoleRepository) RoleService {
	return &roleService{repo: repo}
}

func (s *roleService) Create(ctx context.Context, tenantID string, req domain.RoleCreateReq) (*domain.RoleResp, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, domain.ErrInvalidTenant
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, domain.ErrInvalidArgument
	}
	perms := normalizePermissions(req.Permissions)
	role := &domain.Role{
		Name:        req.Name,
		Scope:       domain.RoleScopeTenant,
		TenantId:    tenantID,
		Permissions: perms,
	}
	if err := s.repo.Create(ctx, tenantID, role); err != nil {
		return nil, err
	}
	return &domain.RoleResp{Name: role.Name, Permissions: role.Permissions}, nil
}

func (s *roleService) List(ctx context.Context, tenantID string) ([]*domain.RoleResp, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, domain.ErrInvalidTenant
	}
	roles, err := s.repo.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.RoleResp, 0, len(roles))
	for _, r := range roles {
		out = append(out, &domain.RoleResp{Name: r.Name, Permissions: r.Permissions})
	}
	return out, nil
}

func (s *roleService) ResolvePermissions(ctx context.Context, tenantID string, roles []string) ([]string, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, domain.ErrInvalidTenant
	}
	perms := map[string]struct{}{}
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		role, err := s.repo.Get(ctx, tenantID, r)
		if err != nil {
			return nil, err
		}
		if role == nil {
			continue
		}
		for _, p := range role.Permissions {
			if p == "" {
				continue
			}
			perms[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(perms))
	for p := range perms {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func normalizePermissions(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
