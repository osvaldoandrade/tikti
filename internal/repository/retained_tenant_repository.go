package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// RetainedTenantRepository is the read-only lifetime authority. Unlike public
// tenant projections it retains tombstones, and never repairs a stored record.
type RetainedTenantRepository interface {
	GetRetained(context.Context, string, time.Time) (*domain.Tenant, error)
}

func (r *tenantRepo) GetRetained(ctx context.Context, tenantID string, observedAt time.Time) (*domain.Tenant, error) {
	if !activeTenantIdentity(tenantID) {
		return nil, domain.ErrInvalidTenant
	}
	if r == nil || r.client == nil || observedAt.IsZero() {
		return nil, errStoredTenantContract
	}
	raw, err := r.client.HGet(ctx, tenantsHash, tenantID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, errStoredTenantContract
	}
	return decodeRetainedTenant(raw, tenantID, observedAt)
}

func decodeRetainedTenant(raw, tenantID string, observedAt time.Time) (*domain.Tenant, error) {
	var tenant domain.Tenant
	if len(raw) == 0 || len(raw) > 4096 || !decodeExactObject(raw, tenantFields, &tenant) ||
		!activeTenantIdentity(tenantID) || tenant.Id != tenantID || tenant.Slug != tenantID ||
		!validTenantName(tenant.Name) || !validTenantStatus(tenant.Status) ||
		tenant.CreatedAt.IsZero() || tenant.CreatedAt.After(observedAt) {
		return nil, domain.ErrTenantInvariant
	}
	// JSON time decoding otherwise accepts aliases such as redundant fractions.
	// Existing canonical zone offsets remain valid; epochs normalize to UTC.
	var timestamps map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &timestamps) != nil || !canonicalStoredTime(timestamps["createdAt"], tenant.CreatedAt) {
		return nil, domain.ErrTenantInvariant
	}
	if tenant.RetiredAt != nil && (tenant.Status != domain.TenantStatusDisabled || tenant.RetiredAt.IsZero() ||
		tenant.RetiredAt.Before(tenant.CreatedAt) || tenant.RetiredAt.After(observedAt) ||
		!canonicalStoredTime(timestamps["retiredAt"], *tenant.RetiredAt)) {
		return nil, domain.ErrTenantInvariant
	}
	return &tenant, nil
}

func canonicalStoredTime(raw json.RawMessage, timestamp time.Time) bool {
	canonical, err := timestamp.MarshalText()
	if err != nil {
		return false
	}
	var value string
	return json.Unmarshal(raw, &value) == nil && value == string(canonical)
}
