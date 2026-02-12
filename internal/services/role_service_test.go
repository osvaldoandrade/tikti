package services

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeRoleRepo struct {
	createFn func(ctx context.Context, tenantID string, role *domain.Role) error
	getFn    func(ctx context.Context, tenantID string, name string) (*domain.Role, error)
	listFn   func(ctx context.Context, tenantID string) ([]*domain.Role, error)
}

func (f *fakeRoleRepo) Create(ctx context.Context, tenantID string, role *domain.Role) error {
	if f.createFn != nil {
		return f.createFn(ctx, tenantID, role)
	}
	return nil
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
