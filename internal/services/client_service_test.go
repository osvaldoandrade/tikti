package services

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeClientRepo struct {
	createFn func(ctx context.Context, tenantID string, client *domain.Client) error
	getFn    func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error)
	listFn   func(ctx context.Context, tenantID string) ([]*domain.Client, error)
}

func (f *fakeClientRepo) Create(ctx context.Context, tenantID string, client *domain.Client) error {
	if f.createFn != nil {
		return f.createFn(ctx, tenantID, client)
	}
	return nil
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
		if !reflect.DeepEqual(client.DefaultScopes, []string{"s2", "s1", "s1"}) {
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

func TestGenerateSecret(t *testing.T) {
	s := generateSecret(16)
	if s == "" {
		t.Fatalf("expected non-empty secret")
	}
}
