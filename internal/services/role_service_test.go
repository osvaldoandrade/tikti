package services

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeRoleRepo struct {
	createFn       func(ctx context.Context, tenantID string, role *domain.Role) error
	createAbsentFn func(context.Context, string, *domain.Role) (*domain.Role, bool, error)
	getFn          func(ctx context.Context, tenantID string, name string) (*domain.Role, error)
	listFn         func(ctx context.Context, tenantID string) ([]*domain.Role, error)
}

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

func (f *fakeRoleRepo) List(ctx context.Context, tenantID string) ([]*domain.Role, error) {
	if f.listFn != nil {
		return f.listFn(ctx, tenantID)
	}
	return nil, nil
}

func TestNewRoleService(t *testing.T) {
	svc := NewRoleService(&fakeRoleRepo{})
	if svc == nil {
		t.Fatalf("expected service")
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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := NewRoleService(&fakeRoleRepo{}).CreateWithName(
				context.Background(), test.tenant, test.role, domain.RolePutReq{Permissions: test.permissions},
			)
			if !errors.Is(err, test.wantErr) || test.wantErr == nil && err != nil {
				t.Fatalf("CreateWithName() error = %v, want %v", err, test.wantErr)
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
	stored.Scope, stored.ResourceId = domain.RoleScopeResource, "legacy-resource"
	replay, created, err := svc.CreateWithName(context.Background(), "bereia", "Bereia-Read", domain.RolePutReq{Permissions: []string{"scope:a", "Scope:B"}})
	if err != nil || created || !reflect.DeepEqual(replay.Permissions, stored.Permissions) {
		t.Fatalf("replay = %+v, %v, %v", replay, created, err)
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
