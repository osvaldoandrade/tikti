package saml

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

// tidDenylist contains attribute names that must never be taken from a SAML
// assertion because tid is always sourced from the URL path.
var tidDenylist = map[string]bool{
	"tid":       true,
	"tenant_id": true,
	"tenantId":  true,
}

// SanitizeAttributes strips tid-like attributes from a SAML assertion's
// attribute map. When a tid-like attribute is found it is deleted, a metric
// is incremented, and an INFO-level log line is emitted.
//
// urlTID is the tenant ID extracted from the URL path and is used only for
// metric labels — it is never overwritten.
func SanitizeAttributes(attrs map[string][]string, urlTID string, m *Metrics) {
	for k := range attrs {
		if tidDenylist[k] {
			log.Printf("saml: ignoring assertion-supplied %q attribute for tid %s", k, urlTID)
			if m != nil {
				m.TIDOverrideIgnored.WithLabelValues(urlTID).Inc()
			}
			delete(attrs, k)
		}
	}
}

// MapAttributes extracts email, name, and roles from a VerifiedAssertion
// using the per-tenant attribute map stored in rec.AttributeMap.
//
// Before extraction, any assertion-supplied tid-like attributes (tid,
// tenant_id, tenantId) are stripped to prevent cross-tenant escalation.
// When such attributes are found a metric is incremented and an INFO log
// is emitted.
//
// First-match semantics: for each Tikti field the mapped IdP attribute names
// are tried in order; the first non-empty value wins.
//
// Email is required. If it cannot be resolved, a ReasonMissingAttribute
// error is returned. Name and roles are optional.
func MapAttributes(va *VerifiedAssertion, rec IdPRecord, urlTID string, m *Metrics) (email, name string, roles []string, err error) {
	SanitizeAttributes(va.Attributes, urlTID, m)

	email = firstValue(va, rec.AttributeMap["email"])
	if email == "" {
		return "", "", nil, &AttrError{Reason: ReasonMissingAttribute, Field: "email"}
	}

	name = firstValue(va, rec.AttributeMap["name"])

	roles = allValues(va, rec.AttributeMap["roles"])
	return email, name, roles, nil
}

// firstValue tries each mapped attribute name in order and returns the first
// non-empty value from the assertion. Returns "" if none found.
func firstValue(va *VerifiedAssertion, keys []string) string {
	for _, k := range keys {
		if vals := va.Attributes[k]; len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
	}
	return ""
}

// allValues collects every value for the first matched attribute key.
// Returns nil (not an empty slice) when no values are found, so callers
// can distinguish "no roles mapped" from "roles mapped but empty".
func allValues(va *VerifiedAssertion, keys []string) []string {
	for _, k := range keys {
		if vals := va.Attributes[k]; len(vals) > 0 {
			return vals
		}
	}
	return nil
}

// AttrError is returned by MapAttributes when a required attribute is missing.
type AttrError struct {
	Reason Reason
	Field  string
}

func (e *AttrError) Error() string {
	return fmt.Sprintf("saml: %s: %s", e.Reason, e.Field)
}

// ---------------------------------------------------------------------------
// JIT provisioning
// ---------------------------------------------------------------------------

// User represents a JIT-provisioned SAML user record.
type User struct {
	ID              string
	Email           string
	Name            string
	Role            string
	ExternalSubject string
	CreatedAt       time.Time
}

// JITProvisioner handles Just-In-Time user provisioning from SAML assertions
// with a Lua SETNX race guard ensuring exactly one creator per identity.
type JITProvisioner struct {
	rdb     *redis.Client
	metrics *Metrics
}

// NewJITProvisioner creates a JITProvisioner backed by the given Redis client.
func NewJITProvisioner(rdb *redis.Client, metrics *Metrics) *JITProvisioner {
	return &JITProvisioner{rdb: rdb, metrics: metrics}
}

// luaJIT atomically checks whether a JIT user record exists:
//   - If the key does not exist, all fields (including id and created_at)
//     are written via HSET and the script returns 1 (created).
//   - If the key exists, mutable fields are updated but id and created_at
//     are preserved, and the script returns 0 (updated).
//
// KEYS[1]  = saml:jit:{tid}:{nameID}
// ARGV     = field1, val1, field2, val2, …
//
// Follows HLD App. A.8.
const luaJIT = `
local key = KEYS[1]
if redis.call('EXISTS', key) == 0 then
  redis.call('HSET', key, unpack(ARGV))
  return 1
end
local eid = redis.call('HGET', key, 'id')
local eca = redis.call('HGET', key, 'created_at')
redis.call('HSET', key, unpack(ARGV))
if eid then redis.call('HSET', key, 'id', eid) end
if eca then redis.call('HSET', key, 'created_at', eca) end
return 0
`

var jitScript = redis.NewScript(luaJIT)

const jitKeyPrefix = "saml:jit:"

func jitKey(tid, nameID string) string {
	return jitKeyPrefix + tid + ":" + nameID
}

// jitUpsert creates or updates a JIT-provisioned user from a SAML assertion.
// It uses a Lua script to guard against concurrent first-login races: among N
// concurrent callers with the same NameID, exactly one observes created=true.
// When created is true the tikti_saml_jit_provisions_total{tid} counter is
// incremented.
func (j *JITProvisioner) jitUpsert(ctx context.Context, rec IdPRecord, va *VerifiedAssertion) (bool, User, error) {
	email := firstAttr(va, "email")
	name := firstAttr(va, "name")
	roles := allAttrs(va, "roles")

	role := "COMPANY_EMPLOYEE"
	if len(roles) > 0 {
		role = roles[0]
	}

	now := time.Now().UTC()
	id := uuid.NewString()

	key := jitKey(rec.TenantID, va.NameID)
	argv := []interface{}{
		"id", id,
		"email", email,
		"name", name,
		"role", role,
		"external_subject", va.NameID,
		"created_at", now.Format(time.RFC3339Nano),
		"auth_source", "saml",
	}

	result, err := jitScript.Run(ctx, j.rdb, []string{key}, argv...).Int64()
	if err != nil {
		return false, User{}, fmt.Errorf("saml: jit lua: %w", err)
	}

	created := result == 1

	// Read back the final state (id/created_at may differ from what we passed
	// when the record already existed).
	fields, err := j.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return false, User{}, fmt.Errorf("saml: jit hgetall: %w", err)
	}

	u := User{
		ID:              fields["id"],
		Email:           fields["email"],
		Name:            fields["name"],
		Role:            fields["role"],
		ExternalSubject: fields["external_subject"],
	}
	if t, err := time.Parse(time.RFC3339Nano, fields["created_at"]); err == nil {
		u.CreatedAt = t
	}

	if created && j.metrics != nil {
		j.metrics.JITProvisions.WithLabelValues(rec.TenantID).Inc()
	}

	return created, u, nil
}
