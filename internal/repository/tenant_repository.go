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
	// Legacy/bootstrap overwrite must honor the same retirement fence as the
	// public create-if-absent path, including a concurrent retirement.
	for attempt := 0; attempt < 8; attempt++ {
		var committed domain.Tenant
		err := r.client.Watch(ctx, func(tx *redis.Tx) error {
			candidate := *tenant
			raw, readErr := tx.HGet(ctx, tenantsHash, tenant.Id).Result()
			if readErr != nil && readErr != redis.Nil {
				return readErr
			}
			if readErr == nil {
				current, err := decodeRetainedTenant(raw, tenant.Id, time.Now().UTC())
				if err != nil {
					return domain.ErrTenantInvariant
				}
				if current.RetiredAt != nil {
					return domain.ErrTenantConflict
				}
				candidate.CreatedAt = current.CreatedAt
				if current.Status == domain.TenantStatusDisabled {
					candidate.Status = domain.TenantStatusDisabled
				}
			}
			// Marshal only after validating the WATCHed lifetime, on every retry.
			data, err := json.Marshal(&candidate)
			if err != nil {
				return err
			}
			if readErr == nil {
				if _, err := decodeRetainedTenant(string(data), tenant.Id, time.Now().UTC()); err != nil {
					return domain.ErrTenantInvariant
				}
			}
			_, writeErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, tenantsHash, tenant.Id, data)
				return nil
			})
			if writeErr == nil {
				committed = candidate
			}
			return writeErr
		}, tenantsHash)
		if err != redis.TxFailedErr {
			if err == nil {
				*tenant = committed
			}
			return err
		}
	}
	return domain.ErrVersionConflict
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
	raw, err := r.client.HGet(ctx, tenantsHash, tenant.Id).Result()
	if err == redis.Nil {
		return nil, false, domain.ErrTenantConflict
	}
	if err != nil {
		return nil, false, err
	}
	// Replay does not issue an authority lease. Observe time after the read so
	// a concurrent retirement between HSETNX and HGET is a retained conflict,
	// rather than appearing to be a future (corrupt) record.
	existing, err := decodeRetainedTenant(raw, tenant.Id, time.Now().UTC())
	if err == nil && existing.RetiredAt != nil {
		return nil, false, domain.ErrTenantConflict
	}
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
		tenant.CreatedAt = time.Now().UTC()
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
	if t.RetiredAt != nil {
		return nil, nil
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
		if tenant.Id == domain.RetiredDefaultTenantID || tenant.RetiredAt != nil {
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

// IsRetired gives installation bootstrap exact proof of intentional retirement.
func (r *tenantRepo) IsRetired(ctx context.Context, tenantID string) (bool, error) {
	if !activeTenantIdentity(tenantID) || tenantID == domain.MasterTenantID {
		return false, domain.ErrInvalidTenant
	}
	raw, err := r.client.HGet(ctx, tenantsHash, tenantID).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	tenant, err := decodeRetainedTenant(raw, tenantID, time.Now().UTC())
	if err != nil {
		return false, domain.ErrTenantInvariant
	}
	return tenant.RetiredAt != nil, nil
}

// Retire revokes identity authority without deleting memberships or runtime
// data. Keeping the registry field reserves the ID against create replay.
func (r *tenantRepo) Retire(ctx context.Context, tenantID string) error {
	if !activeTenantIdentity(tenantID) || tenantID == domain.MasterTenantID {
		return domain.ErrInvalidTenant
	}
	for attempt := 0; attempt < 8; attempt++ {
		err := r.client.Watch(ctx, func(tx *redis.Tx) error {
			raw, err := tx.HGet(ctx, tenantsHash, tenantID).Result()
			if err == redis.Nil {
				return nil
			}
			if err != nil {
				return err
			}
			tenant, err := decodeRetainedTenant(raw, tenantID, time.Now().UTC())
			if err != nil {
				return domain.ErrTenantInvariant
			}
			if tenant.RetiredAt != nil {
				return nil
			}
			now := time.Now().UTC()
			tenant.Status, tenant.RetiredAt = domain.TenantStatusDisabled, &now
			payload, err := json.Marshal(tenant)
			if err != nil {
				return err
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, tenantsHash, tenantID, payload)
				return nil
			})
			return err
		}, tenantsHash)
		if err != redis.TxFailedErr {
			return err
		}
	}
	return domain.ErrVersionConflict
}
