package services

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type RoleService interface {
	// Legacy methods remain available while deterministic administration uses canonical reads and writes.
	Create(ctx context.Context, tenantID string, req domain.RoleCreateReq) (*domain.RoleResp, error)
	CreateWithName(ctx context.Context, tenantID, roleName string, req domain.RolePutReq) (*domain.RoleResp, bool, error)
	GetByName(ctx context.Context, tenantID, roleName string) (*domain.RoleResp, error)
	ListCanonical(ctx context.Context, tenantID string) ([]*domain.RoleResp, error)
	List(ctx context.Context, tenantID string) ([]*domain.RoleResp, error)
	ResolvePermissions(ctx context.Context, tenantID string, roles []string) ([]string, error)
}

type roleService struct {
	repo      repository.RoleRepository
	exactRepo repository.ExactRoleRepository
}

func NewRoleService(repo repository.RoleRepository) RoleService {
	exactRepo, _ := repo.(repository.ExactRoleRepository)
	return &roleService{repo: repo, exactRepo: exactRepo}
}

func (s *roleService) Create(ctx context.Context, tenantID string, req domain.RoleCreateReq) (*domain.RoleResp, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, domain.ErrInvalidTenant
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, domain.ErrInvalidArgument
	}
	perms, valid := canonicalLegacyRolePermissions(req.Permissions)
	if !valid {
		return nil, domain.ErrInvalidArgument
	}
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
	permissions, valid := scopepolicy.CanonicalPermissions(req.Permissions)
	if !validRoleName(roleName) || !valid {
		return nil, false, domain.ErrInvalidArgument
	}
	desired := &domain.Role{
		Name: roleName, Scope: domain.RoleScopeTenant, TenantId: tenantID,
		Permissions: permissions,
	}
	stored, created, err := s.repo.CreateIfAbsent(ctx, tenantID, desired)
	if err != nil {
		return nil, false, fmt.Errorf("create role: %w", err)
	}
	if stored == nil {
		return nil, false, fmt.Errorf("create role: stored role is missing")
	}
	if !exactRoleDefinition(tenantID, roleName, stored) || !sameRoleDefinition(stored, desired) {
		return nil, false, domain.ErrRoleConflict
	}
	return &domain.RoleResp{
		Name: stored.Name, Permissions: append([]string(nil), stored.Permissions...),
	}, created, nil
}

func (s *roleService) GetByName(ctx context.Context, tenantID, roleName string) (*domain.RoleResp, error) {
	if !validRoleTenantID(tenantID) {
		return nil, domain.ErrInvalidTenant
	}
	if !validRoleName(roleName) {
		return nil, domain.ErrInvalidArgument
	}
	if s.exactRepo == nil {
		return nil, fmt.Errorf("get role: exact repository unavailable")
	}
	role, err := s.exactRepo.GetExact(ctx, tenantID, roleName)
	if err != nil {
		return nil, fmt.Errorf("get role: %w", err)
	}
	if role == nil {
		return nil, domain.ErrRoleNotFound
	}
	if !exactRoleDefinition(tenantID, roleName, role) {
		return nil, fmt.Errorf("get role: stored role contract mismatch")
	}
	return roleResponse(role), nil
}

func (s *roleService) ListCanonical(ctx context.Context, tenantID string) ([]*domain.RoleResp, error) {
	if !validRoleTenantID(tenantID) {
		return nil, domain.ErrInvalidTenant
	}
	if s.exactRepo == nil {
		return nil, fmt.Errorf("list roles: exact repository unavailable")
	}
	roles, err := s.exactRepo.ListExact(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	if len(roles) > 500 {
		return nil, fmt.Errorf("list roles: stored role limit exceeded")
	}
	out := make([]*domain.RoleResp, 0, len(roles))
	for _, role := range roles {
		if role == nil || !exactRoleDefinition(tenantID, role.Name, role) {
			return nil, fmt.Errorf("list roles: stored role contract mismatch")
		}
		out = append(out, roleResponse(role))
	}
	sort.Slice(out, func(left, right int) bool { return out[left].Name < out[right].Name })
	for index := 1; index < len(out); index++ {
		if out[index-1].Name == out[index].Name {
			return nil, fmt.Errorf("list roles: duplicate stored role identity")
		}
	}
	return out, nil
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

func roleResponse(role *domain.Role) *domain.RoleResp {
	permissions := make([]string, len(role.Permissions))
	copy(permissions, role.Permissions)
	return &domain.RoleResp{Name: role.Name, Permissions: permissions}
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
		permissions, valid := canonicalLegacyRolePermissions(role.Permissions)
		if !valid {
			return nil, domain.ErrInvalidArgument
		}
		for _, p := range permissions {
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

func canonicalLegacyRolePermissions(values []string) ([]string, bool) {
	normalized := normalizePermissions(values)
	if len(normalized) == 0 {
		return normalized, true
	}
	return scopepolicy.CanonicalPermissions(normalized)
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
	return scopepolicy.ValidCanonicalPermissions(values)
}

func asciiAlphaNumeric(value byte) bool {
	return strings.IndexByte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", value) >= 0
}

func sameRoleDefinition(left, right *domain.Role) bool {
	if left.Name != right.Name || left.Scope != right.Scope || left.TenantId != right.TenantId ||
		left.ResourceId != right.ResourceId || len(left.Permissions) != len(right.Permissions) {
		return false
	}
	leftPermissions := append([]string(nil), left.Permissions...)
	rightPermissions := append([]string(nil), right.Permissions...)
	sort.Strings(leftPermissions)
	sort.Strings(rightPermissions)
	return slices.Equal(leftPermissions, rightPermissions)
}

func exactRoleDefinition(tenantID, name string, role *domain.Role) bool {
	return role != nil && role.Name == name && role.Scope == domain.RoleScopeTenant &&
		role.TenantId == tenantID && role.ResourceId == "" && validRoleName(name) && validRolePermissions(role.Permissions)
}
