package services

import (
	"context"
	"errors"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeTenantRepo struct {
	createFn        func(ctx context.Context, tenant *domain.Tenant) error
	getFn           func(ctx context.Context, tenantID string) (*domain.Tenant, error)
	listFn          func(ctx context.Context, offset uint64, pageSize int64) ([]domain.Tenant, string, error)
	ensureDefaultFn func(ctx context.Context) (*domain.Tenant, error)
}

func (f *fakeTenantRepo) Create(ctx context.Context, tenant *domain.Tenant) error {
	if f.createFn != nil {
		return f.createFn(ctx, tenant)
	}
	return nil
}

func (f *fakeTenantRepo) Get(ctx context.Context, tenantID string) (*domain.Tenant, error) {
	if f.getFn != nil {
		return f.getFn(ctx, tenantID)
	}
	return nil, nil
}

func (f *fakeTenantRepo) List(ctx context.Context, offset uint64, pageSize int64) ([]domain.Tenant, string, error) {
	if f.listFn != nil {
		return f.listFn(ctx, offset, pageSize)
	}
	return []domain.Tenant{}, "", nil
}

func (f *fakeTenantRepo) EnsureDefault(ctx context.Context) (*domain.Tenant, error) {
	if f.ensureDefaultFn != nil {
		return f.ensureDefaultFn(ctx)
	}
	return nil, nil
}

func TestNewTenantService(t *testing.T) {
	svc := NewTenantService(&fakeTenantRepo{})
	if svc == nil {
		t.Fatalf("expected service")
	}
}

func TestTenantService_Create(t *testing.T) {
	svc := NewTenantService(&fakeTenantRepo{})
	if _, err := svc.Create(context.Background(), domain.TenantCreateReq{Name: "", Slug: "a"}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if _, err := svc.Create(context.Background(), domain.TenantCreateReq{Name: "a", Slug: ""}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}

	repoErr := errors.New("repo-fail")
	svc = NewTenantService(&fakeTenantRepo{createFn: func(ctx context.Context, tenant *domain.Tenant) error {
		return repoErr
	}})
	if _, err := svc.Create(context.Background(), domain.TenantCreateReq{Name: "n", Slug: "s"}); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewTenantService(&fakeTenantRepo{createFn: func(ctx context.Context, tenant *domain.Tenant) error {
		if tenant.Id == "" {
			t.Fatalf("expected generated id")
		}
		return nil
	}})
	resp, err := svc.Create(context.Background(), domain.TenantCreateReq{Name: "Name", Slug: "slug"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.Name != "Name" || resp.Slug != "slug" || resp.Status != domain.TenantStatusActive {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestTenantService_Get(t *testing.T) {
	svc := NewTenantService(&fakeTenantRepo{})
	if _, err := svc.Get(context.Background(), " "); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}

	repoErr := errors.New("repo-fail")
	svc = NewTenantService(&fakeTenantRepo{getFn: func(ctx context.Context, tenantID string) (*domain.Tenant, error) {
		return nil, repoErr
	}})
	if _, err := svc.Get(context.Background(), "t1"); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewTenantService(&fakeTenantRepo{getFn: func(ctx context.Context, tenantID string) (*domain.Tenant, error) {
		return nil, nil
	}})
	if _, err := svc.Get(context.Background(), "t1"); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	svc = NewTenantService(&fakeTenantRepo{getFn: func(ctx context.Context, tenantID string) (*domain.Tenant, error) {
		return &domain.Tenant{Id: "t1", Name: "Tenant", Slug: "tenant", Status: domain.TenantStatusActive}, nil
	}})
	resp, err := svc.Get(context.Background(), "t1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.Id != "t1" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
}

func TestTenantService_List(t *testing.T) {
	svc := NewTenantService(&fakeTenantRepo{})
	if _, err := svc.List(context.Background(), 0, 0); err != domain.ErrInvalidArgument {
		t.Fatalf("expected invalid page size, got %v", err)
	}
	repoErr := errors.New("repo-fail")
	svc = NewTenantService(&fakeTenantRepo{listFn: func(context.Context, uint64, int64) ([]domain.Tenant, string, error) {
		return nil, "", repoErr
	}})
	if _, err := svc.List(context.Background(), 0, 20); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}
	svc = NewTenantService(&fakeTenantRepo{listFn: func(_ context.Context, offset uint64, pageSize int64) ([]domain.Tenant, string, error) {
		if offset != 2 || pageSize != 20 {
			t.Fatalf("unexpected pagination: %d %d", offset, pageSize)
		}
		return []domain.Tenant{{Id: "tenant-a", Name: "Tenant A", Slug: "tenant-a", Status: domain.TenantStatusDisabled}}, "22", nil
	}})
	page, err := svc.List(context.Background(), 2, 20)
	if err != nil || len(page.Tenants) != 1 || page.Tenants[0].Status != domain.TenantStatusDisabled || page.NextPageToken != "22" {
		t.Fatalf("unexpected page: %+v err=%v", page, err)
	}
}

func TestTenantService_EnsureDefault(t *testing.T) {
	repoErr := errors.New("repo-fail")
	svc := NewTenantService(&fakeTenantRepo{ensureDefaultFn: func(ctx context.Context) (*domain.Tenant, error) {
		return nil, repoErr
	}})
	if _, err := svc.EnsureDefault(context.Background()); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewTenantService(&fakeTenantRepo{ensureDefaultFn: func(ctx context.Context) (*domain.Tenant, error) {
		return nil, nil
	}})
	if _, err := svc.EnsureDefault(context.Background()); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	svc = NewTenantService(&fakeTenantRepo{ensureDefaultFn: func(ctx context.Context) (*domain.Tenant, error) {
		return &domain.Tenant{Id: "default", Slug: "default", Name: "Default", Status: domain.TenantStatusActive}, nil
	}})
	resp, err := svc.EnsureDefault(context.Background())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.Id != "default" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
}
