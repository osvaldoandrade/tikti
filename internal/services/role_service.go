package services

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type RoleService interface {
	// Four methods preserve the legacy surface while deterministic creation shares permission resolution.
	Create(ctx context.Context, tenantID string, req domain.RoleCreateReq) (*domain.RoleResp, error)
	CreateWithName(ctx context.Context, tenantID, roleName string, req domain.RolePutReq) (*domain.RoleResp, bool, error)
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

func (s *roleService) CreateWithName(
	ctx context.Context, tenantID string, roleName string, req domain.RolePutReq,
) (*domain.RoleResp, bool, error) {
	if !validRoleTenantID(tenantID) {
		return nil, false, domain.ErrInvalidTenant
	}
	if !validRoleName(roleName) || !validRolePermissions(req.Permissions) {
		return nil, false, domain.ErrInvalidArgument
	}
	desired := &domain.Role{
		Name: roleName, Scope: domain.RoleScopeTenant, TenantId: tenantID,
		Permissions: append([]string(nil), req.Permissions...),
	}
	stored, created, err := s.repo.CreateIfAbsent(ctx, tenantID, desired)
	if err != nil {
		return nil, false, fmt.Errorf("create role: %w", err)
	}
	if stored == nil {
		return nil, false, fmt.Errorf("create role: stored role is missing")
	}
	if !sameRoleDefinition(stored, desired) {
		return nil, false, domain.ErrRoleConflict
	}
	return &domain.RoleResp{
		Name: stored.Name, Permissions: append([]string(nil), stored.Permissions...),
	}, created, nil
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

func validRoleTenantID(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, char := range []byte(value) {
		if strings.IndexByte("abcdefghijklmnopqrstuvwxyz0123456789-", char) < 0 {
			return false
		}
	}
	return true
}

func validRoleName(value string) bool {
	if len(value) < 1 || len(value) > 128 || !asciiAlphaNumeric(value[0]) || !asciiAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for _, char := range []byte(value) {
		if !asciiAlphaNumeric(char) && char != '.' && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func validRolePermissions(values []string) bool {
	if len(values) < 1 || len(values) > 500 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(value) < 1 || len(value) > 128 {
			return false
		}
		for _, char := range []byte(value) {
			if !asciiAlphaNumeric(char) && !strings.ContainsRune("._:/*-", rune(char)) {
				return false
			}
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return strings.IndexByte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", value) >= 0
}

func sameRoleDefinition(left, right *domain.Role) bool {
	if left.Name != right.Name || left.TenantId != right.TenantId || len(left.Permissions) != len(right.Permissions) {
		return false
	}
	leftPermissions := append([]string(nil), left.Permissions...)
	rightPermissions := append([]string(nil), right.Permissions...)
	sort.Strings(leftPermissions)
	sort.Strings(rightPermissions)
	return slices.Equal(leftPermissions, rightPermissions)
}
