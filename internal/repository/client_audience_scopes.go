package repository

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// ExistingAudienceScopeReconciler only changes the ceiling of a previously
// observed installation-owned client. It cannot create or adopt clients.
type ExistingAudienceScopeReconciler interface {
	ReconcileCodeAdminAudienceScopes(context.Context, string, *domain.Client, []string) (*domain.Client, error)
}

var existingAudienceScopesScript = redis.NewScript(`
local value = redis.call("HGET", KEYS[1], ARGV[1])
local marker = redis.call("HGET", KEYS[2], ARGV[1])
if not value or value ~= ARGV[2] then return "changed" end
if ARGV[4] == "managed" then
  if marker ~= value then return "changed" end
else
  if marker then return "changed" end
end
redis.call("HSET", KEYS[1], ARGV[1], ARGV[3])
if ARGV[4] == "managed" then redis.call("HSET", KEYS[2], ARGV[1], ARGV[3]) end
return "updated"`)

func (r *clientRepo) ReconcileCodeAdminAudienceScopes(
	ctx context.Context, tenantID string, current *domain.Client, scopes []string,
) (*domain.Client, error) {
	managed := domain.IsManagedCodeAdminAudience(tenantID, current)
	bootstrapHome := current != nil && tenantID == domain.MasterTenantID &&
		current.TenantId == tenantID && current.Id == domain.CodeAdminAudienceClientID &&
		current.Type == domain.ClientTypePublic && current.Status == domain.ClientStatusActive &&
		current.ManagedBy == "" && current.SecretHash == "" &&
		slices.Equal(current.AllowedGrantTypes, []string{string(domain.GrantTypeTokenExchange)})
	if r == nil || r.client == nil || !managed && !bootstrapHome || !scopepolicy.ValidCanonicalAudienceScopes(scopes) {
		return nil, domain.ErrManagedClientConflict
	}
	before, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	desired := *current
	desired.DefaultScopes = append([]string(nil), scopes...)
	after, err := json.Marshal(&desired)
	if err != nil {
		return nil, err
	}
	owner := "bootstrap-home"
	if managed {
		owner = "managed"
	}
	result, err := existingAudienceScopesScript.Run(ctx, r.client,
		[]string{clientsKey(tenantID), managedClientsKey(tenantID)},
		current.Id, before, after, owner).Text()
	if err != nil {
		return nil, err
	}
	if result != "updated" {
		return nil, domain.ErrManagedClientConflict
	}
	return &desired, nil
}
