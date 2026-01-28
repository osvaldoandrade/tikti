package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type TenantRepository interface {
	Create(ctx context.Context, tenant *domain.Tenant) error
	Get(ctx context.Context, tenantID string) (*domain.Tenant, error)
	EnsureDefault(ctx context.Context) (*domain.Tenant, error)
}

type tenantRepo struct {
	client *redis.Client
}

const tenantsHash = "tenants"

func NewTenantRepo(rdb *redis.Client) TenantRepository {
	return &tenantRepo{client: rdb}
}

func (r *tenantRepo) Create(ctx context.Context, tenant *domain.Tenant) error {
	if tenant.Id == "" {
		tenant.Id = uuid.NewString()
	}
	if tenant.Status == "" {
		tenant.Status = domain.TenantStatusActive
	}
	if tenant.CreatedAt.IsZero() {
		tenant.CreatedAt = time.Now()
	}
	data, err := json.Marshal(tenant)
	if err != nil {
		return err
	}
	return r.client.HSet(ctx, tenantsHash, tenant.Id, data).Err()
}

func (r *tenantRepo) Get(ctx context.Context, tenantID string) (*domain.Tenant, error) {
	val, err := r.client.HGet(ctx, tenantsHash, tenantID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if val == "" {
		return nil, nil
	}
	var t domain.Tenant
	if e := json.Unmarshal([]byte(val), &t); e != nil {
		return nil, e
	}
	return &t, nil
}

func (r *tenantRepo) EnsureDefault(ctx context.Context) (*domain.Tenant, error) {
	const defaultTenantID = "default"
	existing, err := r.Get(ctx, defaultTenantID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}
	t := &domain.Tenant{
		Id:     defaultTenantID,
		Slug:   "default",
		Name:   "Default",
		Status: domain.TenantStatusActive,
	}
	if err := r.Create(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}
