package repository

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type TenantRepository interface {
	Create(ctx context.Context, tenant *domain.Tenant) error
	CreateIfAbsent(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, bool, error)
	Get(ctx context.Context, tenantID string) (*domain.Tenant, error)
	List(ctx context.Context, offset uint64, pageSize int64) ([]domain.Tenant, string, error)
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
	prepareTenant(tenant)
	data, err := json.Marshal(tenant)
	if err != nil {
		return err
	}
	return r.client.HSet(ctx, tenantsHash, tenant.Id, data).Err()
}

func (r *tenantRepo) CreateIfAbsent(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, bool, error) {
	prepareTenant(tenant)
	data, err := json.Marshal(tenant)
	if err != nil {
		return nil, false, err
	}
	created, err := r.client.HSetNX(ctx, tenantsHash, tenant.Id, data).Result()
	if err != nil {
		return nil, false, err
	}
	if created {
		return tenant, true, nil
	}
	existing, err := r.Get(ctx, tenant.Id)
	return existing, false, err
}

func prepareTenant(tenant *domain.Tenant) {
	if tenant.Id == "" {
		tenant.Id = uuid.NewString()
	}
	if tenant.Status == "" {
		tenant.Status = domain.TenantStatusActive
	}
	if tenant.CreatedAt.IsZero() {
		tenant.CreatedAt = time.Now()
	}
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

func (r *tenantRepo) List(ctx context.Context, offset uint64, pageSize int64) ([]domain.Tenant, string, error) {
	keys, err := r.client.HKeys(ctx, tenantsHash).Result()
	if err != nil {
		return nil, "", err
	}
	sort.Strings(keys)
	if offset >= uint64(len(keys)) {
		return []domain.Tenant{}, "", nil
	}
	end := offset + uint64(pageSize)
	if end > uint64(len(keys)) {
		end = uint64(len(keys))
	}
	values, err := r.client.HMGet(ctx, tenantsHash, keys[offset:end]...).Result()
	if err != nil {
		return nil, "", err
	}
	tenants := make([]domain.Tenant, 0, len(values))
	for _, value := range values {
		encoded, ok := value.(string)
		if !ok || encoded == "" {
			continue
		}
		var tenant domain.Tenant
		if err := json.Unmarshal([]byte(encoded), &tenant); err != nil {
			return nil, "", err
		}
		tenants = append(tenants, tenant)
	}
	next := ""
	if end < uint64(len(keys)) {
		next = strconv.FormatUint(end, 10)
	}
	return tenants, next, nil
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
