package services

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeClientRepo struct {
	createFn func(ctx context.Context, tenantID string, client *domain.Client) error
	ensureFn func(ctx context.Context, tenantID string, client *domain.Client) (*domain.Client, bool, error)
	getFn    func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error)
	listFn   func(ctx context.Context, tenantID string) ([]*domain.Client, error)
}

func (f *fakeClientRepo) Create(ctx context.Context, tenantID string, client *domain.Client) error {
	if f.createFn != nil {
		return f.createFn(ctx, tenantID, client)
	}
	return nil
}

func (f *fakeClientRepo) EnsureManagedAudience(ctx context.Context, tenantID string, client *domain.Client) (*domain.Client, bool, error) {
	if f.ensureFn != nil {
		return f.ensureFn(ctx, tenantID, client)
	}
	return client, true, nil
}

func (f *fakeClientRepo) Get(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
	if f.getFn != nil {
		return f.getFn(ctx, tenantID, clientID)
	}
	return nil, nil
}

func (f *fakeClientRepo) List(ctx context.Context, tenantID string) ([]*domain.Client, error) {
	if f.listFn != nil {
		return f.listFn(ctx, tenantID)
	}
	return nil, nil
}

func TestNewClientService(t *testing.T) {
	svc := NewClientService(&fakeClientRepo{})
	if svc == nil {
		t.Fatalf("expected service")
	}
}

func TestClientService_Create(t *testing.T) {
	svc := NewClientService(&fakeClientRepo{})
	if _, err := svc.Create(context.Background(), "", domain.ClientCreateReq{ClientId: "c1"}); err != domain.ErrInvalidTenant {
		t.Fatalf("expected ErrInvalidTenant, got %v", err)
	}
	if _, err := svc.Create(context.Background(), "t1", domain.ClientCreateReq{ClientId: ""}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	createCalled := false
	svc = NewClientService(&fakeClientRepo{createFn: func(context.Context, string, *domain.Client) error {
		createCalled = true
		return nil
	}})
	if _, err := svc.Create(context.Background(), "t1", domain.ClientCreateReq{
		ClientId: "c1", DefaultScopes: []string{"code-admin:secrets:read"},
	}); err != nil {
		t.Fatalf("expected runtime-backed tenant scope to be accepted, got %v", err)
	}
	if !createCalled {
		t.Fatal("repository was not called for a runtime-backed tenant scope")
	}

	repoErr := errors.New("repo-fail")
	svc = NewClientService(&fakeClientRepo{createFn: func(ctx context.Context, tenantID string, client *domain.Client) error {
		return repoErr
	}})
	if _, err := svc.Create(context.Background(), "t1", domain.ClientCreateReq{ClientId: "c1"}); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewClientService(&fakeClientRepo{createFn: func(ctx context.Context, tenantID string, client *domain.Client) error {
		if client.SecretHash == "" {
			t.Fatalf("expected secret hash")
		}
		if client.Type != domain.ClientTypePublic {
			t.Fatalf("expected mapped type PUBLIC, got %s", client.Type)
		}
		if !reflect.DeepEqual(client.AllowedGrantTypes, []string{"b", "a", "a"}) {
			t.Fatalf("unexpected grant types: %v", client.AllowedGrantTypes)
		}
		if !reflect.DeepEqual(client.DefaultScopes, []string{"s1", "s2"}) {
			t.Fatalf("unexpected scopes: %v", client.DefaultScopes)
		}
		return nil
	}})
	resp, err := svc.Create(context.Background(), "t1", domain.ClientCreateReq{
		ClientId:          "c1",
		Type:              "public",
		AllowedGrantTypes: []string{" b ", "a", "a"},
		DefaultScopes:     []string{"s2", "s1", "s1"},
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.ClientId != "c1" || resp.Secret == "" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestClientService_Get(t *testing.T) {
	repoErr := errors.New("repo-fail")
	svc := NewClientService(&fakeClientRepo{getFn: func(ctx context.Context, tenantID, clientID string) (*domain.Client, error) {
		return nil, repoErr
	}})
	if _, err := svc.Get(context.Background(), "t1", "c1"); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewClientService(&fakeClientRepo{getFn: func(ctx context.Context, tenantID, clientID string) (*domain.Client, error) {
		return nil, nil
	}})
	if _, err := svc.Get(context.Background(), "t1", "c1"); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	svc = NewClientService(&fakeClientRepo{getFn: func(ctx context.Context, tenantID, clientID string) (*domain.Client, error) {
		return &domain.Client{
			Id:                "c1",
			Type:              domain.ClientTypeService,
			AllowedGrantTypes: []string{"token_exchange"},
			DefaultScopes:     []string{"scope:a"},
		}, nil
	}})
	resp, err := svc.Get(context.Background(), "t1", "c1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.ClientId != "c1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestClientService_List(t *testing.T) {
	repoErr := errors.New("repo-fail")
	svc := NewClientService(&fakeClientRepo{listFn: func(ctx context.Context, tenantID string) ([]*domain.Client, error) {
		return nil, repoErr
	}})
	if _, err := svc.List(context.Background(), "t1"); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}

	svc = NewClientService(&fakeClientRepo{listFn: func(ctx context.Context, tenantID string) ([]*domain.Client, error) {
		return []*domain.Client{{Id: "c1", Type: domain.ClientTypeService}}, nil
	}})
	resp, err := svc.List(context.Background(), "t1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(resp) != 1 || resp[0].ClientId != "c1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestClientService_GetClient(t *testing.T) {
	repoErr := errors.New("repo-fail")
	svc := NewClientService(&fakeClientRepo{getFn: func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return nil, repoErr
	}})
	if _, err := svc.GetClient(context.Background(), "t1", "c1"); !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error, got %v", err)
	}
}

func TestClientService_EnsureCodeAdminAudience(t *testing.T) {
	var captured *domain.Client
	repo := &fakeClientRepo{ensureFn: func(_ context.Context, tenantID string, client *domain.Client) (*domain.Client, bool, error) {
		if tenantID != "bereia" {
			t.Fatalf("unexpected tenant: %s", tenantID)
		}
		copy := *client
		captured = &copy
		return client, true, nil
	}}
	service := NewClientService(repo, WithManagedAudienceClients(true, []string{"bereia"}))
	response, created, err := service.EnsureCodeAdminAudience(context.Background(), "bereia", domain.ManagedAudienceClientEnsureReq{
		DefaultScopes: []string{
			" console:clusters:read ", "code-admin:workloads:read", "code-admin:clusters:read",
			"code-admin:workloads:read",
		},
	})
	if err != nil || !created {
		t.Fatalf("ensure: response=%+v created=%v err=%v", response, created, err)
	}
	wantScopes := []string{"code-admin:clusters:read", "code-admin:workloads:read", "console:clusters:read"}
	if !domain.IsManagedCodeAdminAudience("bereia", captured) || !slices.Equal(captured.DefaultScopes, wantScopes) {
		t.Fatalf("unexpected managed definition: %+v", captured)
	}
	encoded, err := json.Marshal(response)
	if err != nil || strings.Contains(strings.ToLower(string(encoded)), "secret") {
		t.Fatalf("managed response exposes credential material: %s err=%v", encoded, err)
	}
}

func TestClientService_EnsureCodeAdminAudienceFailsClosed(t *testing.T) {
	service := NewClientService(&fakeClientRepo{}, WithManagedAudienceClients(true, []string{"bereia"}))
	for name, test := range map[string]struct {
		tenant string
		scopes []string
		want   error
	}{
		"outside canary": {tenant: "storifly", scopes: []string{"code-admin:workloads:read"}, want: domain.ErrInvalidTenant},
		"invalid tenant": {tenant: " Bereia ", scopes: []string{"code-admin:workloads:read"}, want: domain.ErrInvalidTenant},
		"empty scopes":   {tenant: "bereia", want: domain.ErrInvalidArgument},
		"invented scope": {tenant: "bereia", scopes: []string{"code-admin:invented:read"}, want: domain.ErrInvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := service.EnsureCodeAdminAudience(context.Background(), test.tenant, domain.ManagedAudienceClientEnsureReq{
				DefaultScopes: test.scopes,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
	disabled := NewClientService(&fakeClientRepo{})
	if _, _, err := disabled.EnsureCodeAdminAudience(context.Background(), "bereia", domain.ManagedAudienceClientEnsureReq{
		DefaultScopes: []string{"code-admin:workloads:read"},
	}); !errors.Is(err, domain.ErrInvalidTenant) {
		t.Fatalf("disabled ensure returned %v", err)
	}
	conflict := NewClientService(&fakeClientRepo{ensureFn: func(context.Context, string, *domain.Client) (*domain.Client, bool, error) {
		return nil, false, domain.ErrManagedClientConflict
	}}, WithManagedAudienceClients(true, []string{"bereia"}))
	if _, _, err := conflict.EnsureCodeAdminAudience(context.Background(), "bereia", domain.ManagedAudienceClientEnsureReq{
		DefaultScopes: []string{"code-admin:workloads:read"},
	}); !errors.Is(err, domain.ErrManagedClientConflict) {
		t.Fatalf("conflict returned %v", err)
	}
}

func TestClientService_EnsureCodeAdminAudienceDiscoversOnlyActiveDynamicTenant(t *testing.T) {
	var status = domain.TenantStatusActive
	tenants := &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
		if tenantID != "new-tenant" {
			t.Fatalf("unexpected tenant lookup: %s", tenantID)
		}
		return &domain.Tenant{Id: tenantID, Status: status}, nil
	}}
	service := NewClientService(
		&fakeClientRepo{},
		WithManagedAudienceClients(true, []string{"bereia"}),
		WithDynamicManagedAudienceClients(true, tenants),
	)
	response, created, err := service.EnsureCodeAdminAudience(context.Background(), "new-tenant", domain.ManagedAudienceClientEnsureReq{
		DefaultScopes: []string{"code-admin:workloads:read"},
	})
	if err != nil || !created || response.TenantId != "new-tenant" {
		t.Fatalf("dynamic ensure: response=%+v created=%v err=%v", response, created, err)
	}
	status = domain.TenantStatusDisabled
	if _, _, err = service.EnsureCodeAdminAudience(context.Background(), "new-tenant", domain.ManagedAudienceClientEnsureReq{
		DefaultScopes: []string{"code-admin:workloads:read"},
	}); !errors.Is(err, domain.ErrInvalidTenant) {
		t.Fatalf("disabled dynamic tenant returned %v", err)
	}
	missing := NewClientService(
		&fakeClientRepo{},
		WithDynamicManagedAudienceClients(true, &fakeTenantRepo{}),
	)
	if _, _, err = missing.EnsureCodeAdminAudience(context.Background(), "new-tenant", domain.ManagedAudienceClientEnsureReq{
		DefaultScopes: []string{"code-admin:workloads:read"},
	}); !errors.Is(err, domain.ErrInvalidTenant) {
		t.Fatalf("missing dynamic tenant returned %v", err)
	}
	disabled := NewClientService(
		&fakeClientRepo{},
		WithDynamicManagedAudienceClients(false, tenants),
	)
	if _, _, err = disabled.EnsureCodeAdminAudience(context.Background(), "new-tenant", domain.ManagedAudienceClientEnsureReq{
		DefaultScopes: []string{"code-admin:workloads:read"},
	}); !errors.Is(err, domain.ErrInvalidTenant) {
		t.Fatalf("disabled dynamic discovery returned %v", err)
	}
}

func TestGenerateSecret(t *testing.T) {
	s := generateSecret(16)
	if s == "" {
		t.Fatalf("expected non-empty secret")
	}
}
