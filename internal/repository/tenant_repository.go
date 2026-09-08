package repository

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/internal/tenantname"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type TenantRepository interface {
	Create(ctx context.Context, tenant *domain.Tenant) error
	CreateIfAbsent(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, bool, error)
	Get(ctx context.Context, tenantID string) (*domain.Tenant, error)
	List(ctx context.Context, offset uint64, pageSize int64) ([]domain.Tenant, string, error)
	RetireLegacyDefault(ctx context.Context) (bool, error)
}

type tenantRepo struct {
	client *redis.Client
}

const tenantsHash = "tenants"

func NewTenantRepo(rdb *redis.Client) TenantRepository {
	return &tenantRepo{client: rdb}
}

func (r *tenantRepo) Create(ctx context.Context, tenant *domain.Tenant) error {
	if tenant == nil || tenant.Id == domain.RetiredDefaultTenantID {
		return domain.ErrInvalidArgument
	}
	prepareTenant(tenant)
	data, err := json.Marshal(tenant)
	if err != nil {
		return err
	}
	return r.client.HSet(ctx, tenantsHash, tenant.Id, data).Err()
}

func (r *tenantRepo) CreateIfAbsent(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, bool, error) {
	if tenant == nil || tenant.Id == domain.RetiredDefaultTenantID {
		return nil, false, domain.ErrInvalidArgument
	}
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
	if tenantID == domain.RetiredDefaultTenantID {
		return nil, nil
	}
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
	if pageSize < 1 || pageSize > 200 {
		return nil, "", domain.ErrInvalidArgument
	}
	values, err := r.client.HGetAll(ctx, tenantsHash).Result()
	if err != nil {
		return nil, "", err
	}
	tenants := make([]domain.Tenant, 0, len(values))
	masterCount := 0
	for _, value := range values {
		if value == "" {
			continue
		}
		var tenant domain.Tenant
		if err := json.Unmarshal([]byte(value), &tenant); err != nil {
			return nil, "", err
		}
		if tenant.Id == domain.RetiredDefaultTenantID {
			continue
		}
		if !tenantname.Valid(tenant.Name) {
			return nil, "", domain.ErrTenantInvariant
		}
		if tenant.Id == domain.MasterTenantID {
			masterCount++
			if tenant.Slug != domain.MasterTenantID {
				return nil, "", domain.ErrTenantInvariant
			}
		} else if tenantname.ReservedMaster(tenant.Name) {
			return nil, "", domain.ErrTenantInvariant
		}
		tenants = append(tenants, tenant)
	}
	if masterCount != 1 {
		return nil, "", domain.ErrTenantInvariant
	}
	sort.Slice(tenants, func(left, right int) bool {
		if tenants[left].Id == domain.MasterTenantID {
			return true
		}
		if tenants[right].Id == domain.MasterTenantID {
			return false
		}
		leftName := strings.ToLower(strings.TrimSpace(tenants[left].Name))
		rightName := strings.ToLower(strings.TrimSpace(tenants[right].Name))
		if leftName == rightName {
			return tenants[left].Id < tenants[right].Id
		}
		return leftName < rightName
	})
	if offset >= uint64(len(tenants)) {
		return []domain.Tenant{}, "", nil
	}
	// pageSize is bounded to the positive range [1, 200] above.
	end := offset + uint64(pageSize) // #nosec G115 -- validated positive bounded conversion.
	if end > uint64(len(tenants)) {
		end = uint64(len(tenants))
	}
	page := append([]domain.Tenant(nil), tenants[offset:end]...)
	next := ""
	if end < uint64(len(tenants)) {
		next = strconv.FormatUint(end, 10)
	}
	return page, next, nil
}

// RetireLegacyDefault removes only the obsolete tenant registry entry. The
// tenant's historical memberships and assignments remain untouched for an
// explicit, auditable rollback, but every runtime authority path rejects the
// reserved ID.
func (r *tenantRepo) RetireLegacyDefault(ctx context.Context) (bool, error) {
	removed, err := r.client.HDel(ctx, tenantsHash, domain.RetiredDefaultTenantID).Result()
	return removed == 1, err
}
