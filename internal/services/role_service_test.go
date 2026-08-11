package services

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeRoleRepo struct {
	createFn       func(ctx context.Context, tenantID string, role *domain.Role) error
	createAbsentFn func(context.Context, string, *domain.Role) (*domain.Role, bool, error)
	getFn          func(ctx context.Context, tenantID string, name string) (*domain.Role, error)
	listFn         func(ctx context.Context, tenantID string) ([]*domain.Role, error)
}

type legacyOnlyRoleRepo struct{ repository.RoleRepository }

func (f *fakeRoleRepo) Create(ctx context.Context, tenantID string, role *domain.Role) error {
	if f.createFn != nil {
		return f.createFn(ctx, tenantID, role)
	}
	return nil
}

func (f *fakeRoleRepo) CreateIfAbsent(ctx context.Context, tenantID string, role *domain.Role) (*domain.Role, bool, error) {
	if f.createAbsentFn != nil {
		return f.createAbsentFn(ctx, tenantID, role)
	}
	return role, true, nil
}

func (f *fakeRoleRepo) Get(ctx context.Context, tenantID string, name string) (*domain.Role, error) {
	if f.getFn != nil {
		return f.getFn(ctx, tenantID, name)
	}
	return nil, nil
}

func (f *fakeRoleRepo) GetExact(ctx context.Context, tenantID string, name string) (*domain.Role, error) {
	return f.Get(ctx, tenantID, name)
}

func (f *fakeRoleRepo) List(ctx context.Context, tenantID string) ([]*domain.Role, error) {
	if f.listFn != nil {
		return f.listFn(ctx, tenantID)
	}
	return nil, nil
}

func (f *fakeRoleRepo) ListExact(ctx context.Context, tenantID string) ([]*domain.Role, error) {
	return f.List(ctx, tenantID)
}

func TestNewRoleService(t *testing.T) {
	svc := NewRoleService(&fakeRoleRepo{})
	if svc == nil {
		t.Fatalf("expected service")
	}
}

func TestRoleService_CanonicalReadsRequireExactRepository(t *testing.T) {
	svc := NewRoleService(legacyOnlyRoleRepo{RoleRepository: &fakeRoleRepo{}})
	if _, err := svc.GetByName(context.Background(), "bereia", "read"); err == nil {
		t.Fatal("canonical get accepted a legacy-only repository")
	}
	if _, err := svc.ListCanonical(context.Background(), "bereia"); err == nil {
		t.Fatal("canonical list accepted a legacy-only repository")
	}
}

func TestRoleService_Create(t *testing.T) {
	svc := NewRoleService(&fakeRoleRepo{})
	if _, err := svc.Create(context.Background(), "", domain.RoleCreateReq{Name: "r1"}); err != domain.ErrInvalidTenant {
		t.Fatalf("expected ErrInvalidTenant, got %v", err)
	}
	if _, err := svc.Create(context.Background(), "t1", domain.RoleCreateReq{Name: ""}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}

	repoErr := errors.New("repo-fail")
	svc = NewRoleService(&fakeRoleRepo{createFn: func(ctx context.Context, tenantID string, role *domain.Role) error {
		return repoErr
	}})
	if _, err := svc.Create(context.Background(), "t1", domain.RoleCreateReq{Name: "r1"}); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewRoleService(&fakeRoleRepo{createFn: func(ctx context.Context, tenantID string, role *domain.Role) error {
		if role.Scope != domain.RoleScopeTenant {
			t.Fatalf("expected tenant scope")
		}
		if !reflect.DeepEqual(role.Permissions, []string{"a", "b"}) {
			t.Fatalf("unexpected perms: %v", role.Permissions)
		}
		return nil
	}})
	resp, err := svc.Create(context.Background(), "t1", domain.RoleCreateReq{
		Name:        "r1",
		Permissions: []string{" b", "a", "a", ""},
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.Name != "r1" || !reflect.DeepEqual(resp.Permissions, []string{"a", "b"}) {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestRoleService_List(t *testing.T) {
	svc := NewRoleService(&fakeRoleRepo{})
	if _, err := svc.List(context.Background(), " "); err != domain.ErrInvalidTenant {
		t.Fatalf("expected ErrInvalidTenant, got %v", err)
	}

	repoErr := errors.New("repo-fail")
	svc = NewRoleService(&fakeRoleRepo{listFn: func(ctx context.Context, tenantID string) ([]*domain.Role, error) {
		return nil, repoErr
	}})
	if _, err := svc.List(context.Background(), "t1"); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewRoleService(&fakeRoleRepo{listFn: func(ctx context.Context, tenantID string) ([]*domain.Role, error) {
		return []*domain.Role{{Name: "r1", Permissions: []string{"a"}}}, nil
	}})
	roles, err := svc.List(context.Background(), "t1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(roles) != 1 || roles[0].Name != "r1" {
		t.Fatalf("unexpected response: %+v", roles)
	}
}

func TestRoleService_ResolvePermissions(t *testing.T) {
	svc := NewRoleService(&fakeRoleRepo{})
	if _, err := svc.ResolvePermissions(context.Background(), "", []string{"r1"}); err != domain.ErrInvalidTenant {
		t.Fatalf("expected ErrInvalidTenant, got %v", err)
	}

	repoErr := errors.New("repo-fail")
	svc = NewRoleService(&fakeRoleRepo{getFn: func(ctx context.Context, tenantID string, name string) (*domain.Role, error) {
		return nil, repoErr
	}})
	if _, err := svc.ResolvePermissions(context.Background(), "t1", []string{"r1"}); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewRoleService(&fakeRoleRepo{getFn: func(ctx context.Context, tenantID string, name string) (*domain.Role, error) {
		switch name {
		case "r1":
			return &domain.Role{Name: "r1", Permissions: []string{"p1", "p2", ""}}, nil
		case "r2":
			return &domain.Role{Name: "r2", Permissions: []string{"p2", "p3"}}, nil
		default:
			return nil, nil
		}
	}})
	perms, err := svc.ResolvePermissions(context.Background(), "t1", []string{"r1", " ", "r2", "missing"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !reflect.DeepEqual(perms, []string{"p1", "p2", "p3"}) {
		t.Fatalf("unexpected perms: %v", perms)
	}
}

func TestNormalizePermissions(t *testing.T) {
	got := normalizePermissions([]string{" b", "a", "b", "", "a"})
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected result: got=%v want=%v", got, want)
	}
}

func TestRoleService_CreateWithNameValidationBoundaries(t *testing.T) {
	permissions500 := make([]string, 500)
	for index := range permissions500 {
		permissions500[index] = fmt.Sprintf("scope:%d", index)
	}
	tests := []struct {
		name, tenant, role string
		permissions        []string
		wantErr            error
	}{
		{name: "tenant one", tenant: "0", role: "r", permissions: []string{"p"}},
		{name: "tenant 63", tenant: strings.Repeat("a", 61) + "z9", role: "r", permissions: []string{"p"}},
		{name: "tenant empty", tenant: "", role: "r", permissions: []string{"p"}, wantErr: domain.ErrInvalidTenant},
		{name: "tenant 64", tenant: strings.Repeat("a", 64), role: "r", permissions: []string{"p"}, wantErr: domain.ErrInvalidTenant},
		{name: "tenant syntax", tenant: "Bereia", role: "r", permissions: []string{"p"}, wantErr: domain.ErrInvalidTenant},
		{name: "tenant leading separator", tenant: "-bereia", role: "r", permissions: []string{"p"}, wantErr: domain.ErrInvalidTenant},
		{name: "tenant trailing separator", tenant: "bereia-", role: "r", permissions: []string{"p"}, wantErr: domain.ErrInvalidTenant},
		{name: "role 128", tenant: "t", role: "A_" + strings.Repeat("R", 126), permissions: []string{"p"}},
		{name: "role empty", tenant: "t", role: "", permissions: []string{"p"}, wantErr: domain.ErrInvalidArgument},
		{name: "role 129", tenant: "t", role: strings.Repeat("R", 129), permissions: []string{"p"}, wantErr: domain.ErrInvalidArgument},
		{name: "role unsafe", tenant: "t", role: " role ", permissions: []string{"p"}, wantErr: domain.ErrInvalidArgument},
		{name: "role trailing separator", tenant: "t", role: "role-", permissions: []string{"p"}, wantErr: domain.ErrInvalidArgument},
		{name: "role Unicode", tenant: "t", role: "rôle", permissions: []string{"p"}, wantErr: domain.ErrInvalidArgument},
		{name: "role control", tenant: "t", role: "role\nname", permissions: []string{"p"}, wantErr: domain.ErrInvalidArgument},
		{name: "permission 128", tenant: "t", role: "r", permissions: []string{strings.Repeat("p", 128)}},
		{name: "permissions 500", tenant: "t", role: "r", permissions: permissions500},
		{name: "permissions empty", tenant: "t", role: "r", permissions: []string{}, wantErr: domain.ErrInvalidArgument},
		{name: "permission empty", tenant: "t", role: "r", permissions: []string{""}, wantErr: domain.ErrInvalidArgument},
		{name: "permission 129", tenant: "t", role: "r", permissions: []string{strings.Repeat("p", 129)}, wantErr: domain.ErrInvalidArgument},
		{name: "permissions 501", tenant: "t", role: "r", permissions: append(permissions500, "extra"), wantErr: domain.ErrInvalidArgument},
		{name: "duplicate exact", tenant: "t", role: "r", permissions: []string{"p", "p"}, wantErr: domain.ErrInvalidArgument},
		{name: "permission whitespace", tenant: "t", role: "r", permissions: []string{" scope "}, wantErr: domain.ErrInvalidArgument},
		{name: "permission control", tenant: "t", role: "r", permissions: []string{"scope:\nread"}, wantErr: domain.ErrInvalidArgument},
		{name: "permission Unicode", tenant: "t", role: "r", permissions: []string{"escopo:leitura" + "ç"}, wantErr: domain.ErrInvalidArgument},
		{name: "tenant scope", tenant: "t", role: "r", permissions: []string{"code-admin:services:read"}},
		{name: "identity write", tenant: "t", role: "r", permissions: []string{"code-admin:identity:write"}},
		{name: "global reserved", tenant: "t", role: "r", permissions: []string{"code-admin:tenants:admin"}, wantErr: domain.ErrInvalidArgument},
		{name: "mixed reserved", tenant: "t", role: "r", permissions: []string{"code-admin:repositories:read"}, wantErr: domain.ErrInvalidArgument},
		{name: "nonassignable reserved", tenant: "t", role: "r", permissions: []string{"code-admin:owners:delegate"}, wantErr: domain.ErrInvalidArgument},
		{name: "unknown reserved", tenant: "t", role: "r", permissions: []string{"code-admin:unknown:read"}, wantErr: domain.ErrInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			repo := &fakeRoleRepo{createAbsentFn: func(_ context.Context, _ string, role *domain.Role) (*domain.Role, bool, error) {
				called = true
				return role, true, nil
			}}
			_, _, err := NewRoleService(repo).CreateWithName(
				context.Background(), test.tenant, test.role, domain.RolePutReq{Permissions: test.permissions},
			)
			if !errors.Is(err, test.wantErr) || test.wantErr == nil && err != nil || called != (test.wantErr == nil) {
				t.Fatalf("CreateWithName() error = %v, want %v, repository called=%v", err, test.wantErr, called)
			}
		})
	}
}

func TestRoleService_CreateWithNameReplayConflictAndPreservation(t *testing.T) {
	var stored *domain.Role
	repo := &fakeRoleRepo{createAbsentFn: func(_ context.Context, _ string, role *domain.Role) (*domain.Role, bool, error) {
		if stored == nil {
			copy := *role
			copy.Permissions = append([]string(nil), role.Permissions...)
			stored = &copy
			return stored, true, nil
		}
		return stored, false, nil
	}}
	svc := NewRoleService(repo)
	first, created, err := svc.CreateWithName(context.Background(), "bereia", "Bereia-Read", domain.RolePutReq{Permissions: []string{"Scope:B", "scope:a"}})
	if err != nil || !created || first.Name != "Bereia-Read" || !reflect.DeepEqual(first.Permissions, []string{"Scope:B", "scope:a"}) {
		t.Fatalf("first create = %+v, %v, %v", first, created, err)
	}
	replay, created, err := svc.CreateWithName(context.Background(), "bereia", "Bereia-Read", domain.RolePutReq{Permissions: []string{"scope:a", "Scope:B"}})
	if err != nil || created || !reflect.DeepEqual(replay.Permissions, stored.Permissions) {
		t.Fatalf("idempotent replay = %+v, %v, %v", replay, created, err)
	}
	stored.Scope, stored.ResourceId = domain.RoleScopeResource, "legacy-resource"
	if replay, created, err = svc.CreateWithName(context.Background(), "bereia", "Bereia-Read", domain.RolePutReq{Permissions: []string{"scope:a", "Scope:B"}}); replay != nil || created || !errors.Is(err, domain.ErrRoleConflict) {
		t.Fatalf("corrupt replay = %+v, %v, %v", replay, created, err)
	}
	snapshot := *stored
	if _, _, err = svc.CreateWithName(context.Background(), "bereia", stored.Name, domain.RolePutReq{Permissions: []string{"scope:write"}}); !errors.Is(err, domain.ErrRoleConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	if !reflect.DeepEqual(*stored, snapshot) {
		t.Fatalf("conflict overwrote stored role: %+v", stored)
	}
}

func TestRoleService_CreateWithNameStorageFailures(t *testing.T) {
	repoErr := errors.New("redis unavailable")
	tests := []struct {
		name string
		repo *fakeRoleRepo
	}{
		{name: "repository", repo: &fakeRoleRepo{createAbsentFn: func(context.Context, string, *domain.Role) (*domain.Role, bool, error) { return nil, false, repoErr }}},
		{name: "missing stored role", repo: &fakeRoleRepo{createAbsentFn: func(context.Context, string, *domain.Role) (*domain.Role, bool, error) { return nil, false, nil }}},
		{name: "mismatched tenant", repo: &fakeRoleRepo{createAbsentFn: func(_ context.Context, _ string, role *domain.Role) (*domain.Role, bool, error) {
			stored := *role
			stored.TenantId = "other"
			return &stored, false, nil
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := NewRoleService(test.repo).CreateWithName(context.Background(), "bereia", "read", domain.RolePutReq{Permissions: []string{"p"}})
			if err == nil {
				t.Fatal("expected storage contract error")
			}
		})
	}
}

func TestRoleService_GetByNameCanonicalContract(t *testing.T) {
	stored := &domain.Role{Name: "bereia-read", Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{"scope:read"}}
	svc := NewRoleService(&fakeRoleRepo{getFn: func(_ context.Context, tenantID, name string) (*domain.Role, error) {
		if tenantID != "bereia" || name != stored.Name {
			t.Fatalf("repository target = %q %q", tenantID, name)
		}
		return stored, nil
	}})
	got, err := svc.GetByName(context.Background(), "bereia", stored.Name)
	if err != nil || got.Name != stored.Name || !reflect.DeepEqual(got.Permissions, stored.Permissions) {
		t.Fatalf("GetByName() = %+v, %v", got, err)
	}
	got.Permissions[0] = "mutated"
	if stored.Permissions[0] != "scope:read" {
		t.Fatalf("response aliased stored permissions: %+v", stored)
	}

	for _, test := range []struct {
		name, tenant, role string
		wantErr            error
	}{
		{name: "invalid tenant", tenant: "Bereia", role: "read", wantErr: domain.ErrInvalidTenant},
		{name: "invalid role", tenant: "bereia", role: "read/../../secret", wantErr: domain.ErrInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRoleService(&fakeRoleRepo{}).GetByName(context.Background(), test.tenant, test.role)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("GetByName() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestRoleService_GetByNameMissingAndStorageFailures(t *testing.T) {
	repoFailure := errors.New("redis credential canary")
	for _, test := range []struct {
		name string
		repo *fakeRoleRepo
		want error
	}{
		{name: "missing", repo: &fakeRoleRepo{}, want: domain.ErrRoleNotFound},
		{name: "repository", repo: &fakeRoleRepo{getFn: func(context.Context, string, string) (*domain.Role, error) { return nil, repoFailure }}, want: repoFailure},
		{name: "wrong tenant in storage", repo: &fakeRoleRepo{getFn: func(context.Context, string, string) (*domain.Role, error) {
			return &domain.Role{Name: "read", TenantId: "storifly"}, nil
		}}},
		{name: "wrong name in storage", repo: &fakeRoleRepo{getFn: func(context.Context, string, string) (*domain.Role, error) {
			return &domain.Role{Name: "write", TenantId: "bereia"}, nil
		}}},
		{name: "invalid permissions in storage", repo: &fakeRoleRepo{getFn: func(context.Context, string, string) (*domain.Role, error) {
			return &domain.Role{Name: "read", TenantId: "bereia", Permissions: []string{"scope:read", "scope:read"}}, nil
		}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRoleService(test.repo).GetByName(context.Background(), "bereia", "read")
			if err == nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("GetByName() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRoleService_ListCanonicalDeterministicAndIsolated(t *testing.T) {
	stored := []*domain.Role{
		{Name: "z-admin", Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{"z:admin"}},
		{Name: "a-read", Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{"a:read"}},
	}
	svc := NewRoleService(&fakeRoleRepo{listFn: func(context.Context, string) ([]*domain.Role, error) { return stored, nil }})
	got, err := svc.ListCanonical(context.Background(), "bereia")
	if err != nil || len(got) != 2 || got[0].Name != "a-read" || got[1].Name != "z-admin" {
		t.Fatalf("ListCanonical() = %+v, %v", got, err)
	}
	got[0].Permissions[0] = "mutated"
	if stored[1].Permissions[0] != "a:read" {
		t.Fatalf("response aliased stored permissions: %+v", stored)
	}
	empty, err := NewRoleService(&fakeRoleRepo{}).ListCanonical(context.Background(), "bereia")
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty list = %#v, %v", empty, err)
	}
	roles500 := canonicalRoles(500)
	maximum, err := NewRoleService(&fakeRoleRepo{listFn: func(context.Context, string) ([]*domain.Role, error) {
		return roles500, nil
	}}).ListCanonical(context.Background(), "bereia")
	if err != nil || len(maximum) != 500 {
		t.Fatalf("500-role boundary = %d, %v", len(maximum), err)
	}
}

func TestRoleService_ListCanonicalRejectsInvalidOrCorruptState(t *testing.T) {
	repoFailure := errors.New("redis credential canary")
	for _, test := range []struct {
		name, tenant string
		repo         *fakeRoleRepo
		want         error
	}{
		{name: "invalid tenant", tenant: "../bereia", repo: &fakeRoleRepo{}, want: domain.ErrInvalidTenant},
		{name: "repository", tenant: "bereia", repo: &fakeRoleRepo{listFn: func(context.Context, string) ([]*domain.Role, error) { return nil, repoFailure }}, want: repoFailure},
		{name: "nil role", tenant: "bereia", repo: &fakeRoleRepo{listFn: func(context.Context, string) ([]*domain.Role, error) { return []*domain.Role{nil}, nil }}},
		{name: "wrong tenant", tenant: "bereia", repo: &fakeRoleRepo{listFn: func(context.Context, string) ([]*domain.Role, error) {
			return []*domain.Role{{Name: "read", TenantId: "storifly"}}, nil
		}}},
		{name: "invalid stored name", tenant: "bereia", repo: &fakeRoleRepo{listFn: func(context.Context, string) ([]*domain.Role, error) {
			return []*domain.Role{{Name: "../read", TenantId: "bereia"}}, nil
		}}},
		{name: "duplicate stored name", tenant: "bereia", repo: &fakeRoleRepo{listFn: func(context.Context, string) ([]*domain.Role, error) {
			return []*domain.Role{{Name: "read", TenantId: "bereia", Permissions: []string{"read"}}, {Name: "read", TenantId: "bereia", Permissions: []string{"read"}}}, nil
		}}},
		{name: "invalid stored permissions", tenant: "bereia", repo: &fakeRoleRepo{listFn: func(context.Context, string) ([]*domain.Role, error) {
			return []*domain.Role{{Name: "read", TenantId: "bereia", Permissions: []string{}}}, nil
		}}},
		{name: "stored role limit", tenant: "bereia", repo: &fakeRoleRepo{listFn: func(context.Context, string) ([]*domain.Role, error) {
			return canonicalRoles(501), nil
		}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRoleService(test.repo).ListCanonical(context.Background(), test.tenant)
			if err == nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("ListCanonical() error = %v, want %v", err, test.want)
			}
		})
	}
}

func canonicalRoles(count int) []*domain.Role {
	roles := make([]*domain.Role, count)
	for index := range roles {
		roles[index] = &domain.Role{Name: fmt.Sprintf("role-%03d", index), Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{"read"}}
	}
	return roles
}

func FuzzRoleServiceCanonicalReadIdentifiers(f *testing.F) {
	for _, seed := range [][2]string{{"bereia", "bereia-read"}, {"../bad", "read"}, {"bereia", "read/secret"}, {"0", "A"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, tenantID, roleName string) {
		if len(tenantID) > 256 || len(roleName) > 256 {
			return
		}
		svc := NewRoleService(&fakeRoleRepo{})
		_, _ = svc.GetByName(context.Background(), tenantID, roleName)
		_, _ = svc.ListCanonical(context.Background(), tenantID)
	})
}
