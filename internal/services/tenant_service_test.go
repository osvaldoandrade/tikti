package services

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeTenantRepo struct {
	createFn        func(ctx context.Context, tenant *domain.Tenant) error
	createAbsentFn  func(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, bool, error)
	getFn           func(ctx context.Context, tenantID string) (*domain.Tenant, error)
	listFn          func(ctx context.Context, offset uint64, pageSize int64) ([]domain.Tenant, string, error)
	ensureDefaultFn func(ctx context.Context) (*domain.Tenant, error)
}

func (f *fakeTenantRepo) CreateIfAbsent(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, bool, error) {
	if f.createAbsentFn != nil {
		return f.createAbsentFn(ctx, tenant)
	}
	return tenant, true, nil
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

func TestTenantService_CreateWithID(t *testing.T) {
	var stored *domain.Tenant
	repo := &fakeTenantRepo{createAbsentFn: func(
		ctx context.Context,
		tenant *domain.Tenant,
	) (*domain.Tenant, bool, error) {
		if stored == nil {
			copy := *tenant
			stored = &copy
			return stored, true, nil
		}
		return stored, false, nil
	}}
	svc := NewTenantService(repo)
	req := domain.TenantCreateReq{Name: " Bereia ", Slug: "bereia"}

	createdTenant, created, err := svc.CreateWithID(context.Background(), "bereia", req)
	if err != nil || !created || createdTenant.Id != "bereia" || createdTenant.Name != "Bereia" {
		t.Fatalf("unexpected deterministic create: tenant=%+v created=%v err=%v", createdTenant, created, err)
	}
	stored.Status = domain.TenantStatusDisabled
	stored.CreatedAt = time.Unix(1_700_000_000, 0).UTC()
	snapshot := *stored
	replayed, created, err := svc.CreateWithID(context.Background(), "bereia", req)
	if err != nil || created || replayed.Status != snapshot.Status || replayed.CreatedAt != snapshot.CreatedAt {
		t.Fatalf("unexpected semantic replay: tenant=%+v created=%v err=%v", replayed, created, err)
	}
	_, _, err = svc.CreateWithID(context.Background(), "bereia", domain.TenantCreateReq{
		Name: "Different", Slug: "bereia",
	})
	if !errors.Is(err, domain.ErrTenantConflict) || *stored != snapshot {
		t.Fatalf("expected conflict without overwrite, stored=%+v err=%v", stored, err)
	}
}

func TestTenantService_CreateWithIDValidation(t *testing.T) {
	longName := strings.Repeat("n", 129)
	tests := []struct {
		name     string
		tenantID string
		req      domain.TenantCreateReq
	}{
		{name: "empty id", tenantID: "", req: domain.TenantCreateReq{Name: "Bereia", Slug: ""}},
		{name: "uppercase id", tenantID: "Bereia", req: domain.TenantCreateReq{Name: "Bereia", Slug: "bereia"}},
		{name: "spaced id", tenantID: " bereia ", req: domain.TenantCreateReq{Name: "Bereia", Slug: "bereia"}},
		{name: "long id", tenantID: strings.Repeat("a", 64), req: domain.TenantCreateReq{Name: "Bereia", Slug: "bereia"}},
		{name: "invalid slug", tenantID: "bereia", req: domain.TenantCreateReq{Name: "Bereia", Slug: "bereia_org"}},
		{name: "spaced slug", tenantID: "bereia", req: domain.TenantCreateReq{Name: "Bereia", Slug: " bereia "}},
		{name: "slug differs from id", tenantID: "bereia", req: domain.TenantCreateReq{Name: "Bereia", Slug: "other"}},
		{name: "empty name", tenantID: "bereia", req: domain.TenantCreateReq{Name: "", Slug: "bereia"}},
		{name: "long name", tenantID: "bereia", req: domain.TenantCreateReq{Name: longName, Slug: "bereia"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			svc := NewTenantService(&fakeTenantRepo{})
			if _, _, err := svc.CreateWithID(context.Background(), test.tenantID, test.req); !errors.Is(err, domain.ErrInvalidArgument) {
				t.Fatalf("expected invalid argument, got %v", err)
			}
		})
	}
}

func TestTenantService_CreateWithIDAcceptsExactBoundaries(t *testing.T) {
	tests := []struct {
		tenantID string
		name     string
	}{
		{tenantID: "a", name: "x"},
		{tenantID: strings.Repeat("a", 63), name: strings.Repeat("é", 128)},
	}
	for _, test := range tests {
		t.Run(test.tenantID, func(t *testing.T) {
			response, created, err := NewTenantService(&fakeTenantRepo{}).CreateWithID(
				context.Background(),
				test.tenantID,
				domain.TenantCreateReq{Name: test.name, Slug: test.tenantID},
			)
			if err != nil || !created || response.Id != test.tenantID {
				t.Fatalf("expected accepted boundary, response=%+v created=%v err=%v", response, created, err)
			}
		})
	}
}

func TestTenantService_CreateWithIDRepositoryFailures(t *testing.T) {
	repositoryError := errors.New("repository failure")
	tests := []struct {
		name string
		repo *fakeTenantRepo
	}{
		{
			name: "repository error",
			repo: &fakeTenantRepo{createAbsentFn: func(
				context.Context,
				*domain.Tenant,
			) (*domain.Tenant, bool, error) {
				return nil, false, repositoryError
			}},
		},
		{
			name: "missing stored tenant",
			repo: &fakeTenantRepo{createAbsentFn: func(
				context.Context,
				*domain.Tenant,
			) (*domain.Tenant, bool, error) {
				return nil, false, nil
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := NewTenantService(test.repo).CreateWithID(
				context.Background(),
				"bereia",
				domain.TenantCreateReq{Name: "Bereia", Slug: "bereia"},
			)
			if err == nil {
				t.Fatal("expected repository failure")
			}
			if test.name == "repository error" && !errors.Is(err, repositoryError) {
				t.Fatalf("expected wrapped repository error, got %v", err)
			}
		})
	}
}

func TestTenantService_CreateWithIDConcurrentMismatch(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	svc := NewTenantService(repository.NewTenantRepo(client))

	var created atomic.Int32
	var conflicts atomic.Int32
	var wg sync.WaitGroup
	for index := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := "Bereia"
			if index%2 == 1 {
				name = "Other"
			}
			_, wasCreated, err := svc.CreateWithID(context.Background(), "bereia", domain.TenantCreateReq{
				Name: name, Slug: "bereia",
			})
			if wasCreated {
				created.Add(1)
			}
			if errors.Is(err, domain.ErrTenantConflict) {
				conflicts.Add(1)
			} else if err != nil {
				t.Errorf("unexpected create error: %v", err)
			}
		}()
	}
	wg.Wait()
	if created.Load() != 1 || conflicts.Load() != 16 {
		t.Fatalf("expected one creator and 16 conflicts, got creators=%d conflicts=%d", created.Load(), conflicts.Load())
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
