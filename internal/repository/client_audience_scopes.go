package repository

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

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
	bootstrapHome := tenantID == domain.MasterTenantID && domain.IsBootstrapLegacyCodeAdminAudience(tenantID, current)
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
	// Kvrocks prefixes cache misses with ERR NOSCRIPT, which go-redis v8
	// does not recognize for its EVALSHA fallback. Execute this CAS directly.
	result, err := existingAudienceScopesScript.Eval(ctx, r.client,
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

// CodeAdminAudienceScopeRaiser additively raises the ceiling of a tenant's
// existing managed code-admin-api client, or of the bootstrap's legacy PUBLIC
// home audience. It never creates, adopts, converts, removes a scope from, or
// otherwise edits the client.
type CodeAdminAudienceScopeRaiser interface {
	RaiseManagedCodeAdminAudienceScopes(ctx context.Context, tenantID string, scopes []string) (*domain.Client, bool, error)
}

// RaiseManagedCodeAdminAudienceScopes adds scopes to the code-admin-api client
// of tenantID with a compare-and-swap on the exact stored record and its
// managed marker. A missing client, an unmanaged look-alike, another owner or
// an inactive record conflicts. A ceiling that already contains every scope is
// an exact replay that writes nothing.
//
// Besides the managed SERVICE record, exactly the bootstrap's legacy PUBLIC
// home audience (domain.IsBootstrapLegacyCodeAdminAudience: same tenant,
// code-admin-api, PUBLIC, token_exchange only, no secret, no owner, ACTIVE)
// with canonical scopes is raised. It is the MASTER/home Console audience the
// bootstrap creates and production never re-runs (the installation upgrades
// with --no-hooks). Only the bootstrap can have written it: generic client
// creation (ClientService.Create) always stores a secret, and every other
// writer stores a managed record. Any secret-bearing PUBLIC or unowned SERVICE
// look-alike therefore still conflicts. The legacy shape is preserved (no
// type/owner conversion, no marker) so a later bootstrap run still adopts it.
func (r *clientRepo) RaiseManagedCodeAdminAudienceScopes(ctx context.Context, tenantID string, scopes []string) (*domain.Client, bool, error) {
	additions, ok := scopepolicy.CanonicalAudienceScopes(scopes)
	if r == nil || r.client == nil || !activeTenantIdentity(tenantID) || !ok || !slices.Equal(additions, scopes) {
		return nil, false, domain.ErrInvalidArgument
	}
	keys := []string{clientsKey(tenantID), managedClientsKey(tenantID)}
	for range 4 {
		values, err := managedClientGetScript.Eval(ctx, r.client, keys, domain.CodeAdminAudienceClientID).StringSlice()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, false, err
		}
		if err != nil || len(values) != 2 {
			return nil, false, errStoredManagedClientContract
		}
		var current *domain.Client
		legacy := false
		switch values[0] {
		case "missing":
			return nil, false, domain.ErrManagedClientConflict
		case "legacy":
			candidate, decoded := decodeBootstrapLegacyCodeAdminAudience(tenantID, values[1])
			if !decoded {
				return nil, false, domain.ErrManagedClientConflict
			}
			current, legacy = candidate, true
		case "managed":
			candidate, decoded := decodeManagedAudienceClient(tenantID, values[1])
			if !decoded {
				return nil, false, errStoredManagedClientContract
			}
			if !domain.IsManagedCodeAdminAudience(tenantID, candidate) {
				return nil, false, domain.ErrManagedClientConflict
			}
			current = candidate
		default:
			return nil, false, errStoredManagedClientContract
		}
		missing := false
		for _, scope := range additions {
			if !slices.Contains(current.DefaultScopes, scope) {
				missing = true
				break
			}
		}
		if !missing {
			return current, false, nil
		}
		raised, valid := scopepolicy.CanonicalAudienceScopes(append(slices.Clone(current.DefaultScopes), additions...))
		if !valid {
			return nil, false, domain.ErrManagedClientConflict
		}
		next := *current
		next.DefaultScopes = raised
		if legacy {
			stored, retry, legacyErr := r.raiseBootstrapLegacyCodeAdminAudience(ctx, tenantID, keys, values[1], &next)
			if retry {
				continue
			}
			if legacyErr != nil {
				return nil, false, legacyErr
			}
			return stored, true, nil
		}
		if !validManagedAudienceClient(tenantID, &next) {
			return nil, false, domain.ErrManagedClientConflict
		}
		payload, marshalErr := json.Marshal(&next)
		if marshalErr != nil {
			return nil, false, marshalErr
		}
		updated, updateErr := managedClientReconcileScript.Eval(ctx, r.client, keys, domain.CodeAdminAudienceClientID, values[1], payload).StringSlice()
		if errors.Is(updateErr, context.Canceled) || errors.Is(updateErr, context.DeadlineExceeded) {
			return nil, false, updateErr
		}
		if updateErr != nil || len(updated) != 2 {
			return nil, false, errStoredManagedClientContract
		}
		if updated[0] == "changed" {
			continue
		}
		if updated[0] != "updated" || updated[1] != string(payload) {
			return nil, false, errStoredManagedClientContract
		}
		stored, ok := decodeManagedAudienceClient(tenantID, updated[1])
		if !ok || !domain.IsManagedCodeAdminAudience(tenantID, stored) || !slices.Equal(stored.DefaultScopes, raised) {
			return nil, false, errStoredManagedClientContract
		}
		return stored, true, nil
	}
	return nil, false, domain.ErrManagedClientConflict
}

// raiseBootstrapLegacyCodeAdminAudience swaps the exact stored legacy record
// for next only while it is still unmarked and byte-identical. It reports
// retry when a concurrent writer changed the record or added a marker.
func (r *clientRepo) raiseBootstrapLegacyCodeAdminAudience(
	ctx context.Context, tenantID string, keys []string, before string, next *domain.Client,
) (*domain.Client, bool, error) {
	if !domain.IsBootstrapLegacyCodeAdminAudience(tenantID, next) || !scopepolicy.ValidCanonicalAudienceScopes(next.DefaultScopes) {
		return nil, false, domain.ErrManagedClientConflict
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return nil, false, err
	}
	result, err := existingAudienceScopesScript.Eval(ctx, r.client, keys,
		domain.CodeAdminAudienceClientID, before, payload, "bootstrap-home").Text()
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, false, err
	}
	if err != nil {
		return nil, false, errStoredManagedClientContract
	}
	switch result {
	case "changed":
		return nil, true, nil
	case "updated":
	default:
		return nil, false, errStoredManagedClientContract
	}
	stored, ok := decodeBootstrapLegacyCodeAdminAudience(tenantID, string(payload))
	if !ok || !slices.Equal(stored.DefaultScopes, next.DefaultScopes) {
		return nil, false, errStoredManagedClientContract
	}
	return stored, false, nil
}

// decodeBootstrapLegacyCodeAdminAudience strictly decodes an unmarked record
// and accepts only the bootstrap's legacy home audience with canonical scopes.
func decodeBootstrapLegacyCodeAdminAudience(tenantID, value string) (*domain.Client, bool) {
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var client domain.Client
	if decoder.Decode(&client) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		!domain.IsBootstrapLegacyCodeAdminAudience(tenantID, &client) ||
		!scopepolicy.ValidCanonicalAudienceScopes(client.DefaultScopes) {
		return nil, false
	}
	return &client, true
}
