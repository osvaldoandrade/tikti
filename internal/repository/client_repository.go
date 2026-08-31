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

type ClientRepository interface {
	Create(ctx context.Context, tenantID string, client *domain.Client) error
	EnsureManagedAudience(ctx context.Context, tenantID string, client *domain.Client) (*domain.Client, bool, error)
	Get(ctx context.Context, tenantID string, clientID string) (*domain.Client, error)
	List(ctx context.Context, tenantID string) ([]*domain.Client, error)
}

type clientRepo struct {
	client *redis.Client
}

func NewClientRepo(rdb *redis.Client) ClientRepository {
	return &clientRepo{client: rdb}
}

var (
	errStoredManagedClientContract = errors.New("stored managed client contract mismatch")
	legacyClientCreateScript       = redis.NewScript(`
if redis.call("HEXISTS", KEYS[2], ARGV[1]) == 1 then return "protected" end
local existing = redis.call("HGET", KEYS[1], ARGV[1])
if existing and string.find(existing, ARGV[3], 1, true) then return "corrupt" end
redis.call("HSET", KEYS[1], ARGV[1], ARGV[2])
return "stored"`)
	managedClientEnsureScript = redis.NewScript(`
local value = redis.call("HGET", KEYS[1], ARGV[1])
local marker = redis.call("HGET", KEYS[2], ARGV[1])
if not value and not marker then
  redis.call("HSET", KEYS[1], ARGV[1], ARGV[2])
  redis.call("HSET", KEYS[2], ARGV[1], ARGV[2])
  return {"created", ARGV[2]}
end
if value and not marker then return {"shadow", value} end
if marker and not value then return {"corrupt", ""} end
if marker ~= value then return {"corrupt", ""} end
return {"existing", value}`)
	managedClientReconcileScript = redis.NewScript(`
local value = redis.call("HGET", KEYS[1], ARGV[1])
local marker = redis.call("HGET", KEYS[2], ARGV[1])
if not value or not marker then return {"changed", value or ""} end
if value ~= ARGV[2] or marker ~= ARGV[2] then return {"changed", value} end
redis.call("HSET", KEYS[1], ARGV[1], ARGV[3])
redis.call("HSET", KEYS[2], ARGV[1], ARGV[3])
return {"updated", ARGV[3]}`)
	managedClientGetScript = redis.NewScript(`
local value = redis.call("HGET", KEYS[1], ARGV[1])
local marker = redis.call("HGET", KEYS[2], ARGV[1])
if not value and not marker then return {"missing", ""} end
if value and not marker then return {"legacy", value} end
if marker and not value then return {"corrupt", ""} end
if marker ~= value then return {"corrupt", ""} end
return {"managed", value}`)
	managedClientListScript = redis.NewScript(`
return cjson.encode({clients=redis.call("HGETALL", KEYS[1]), markers=redis.call("HGETALL", KEYS[2])})`)
)

func (r *clientRepo) Create(ctx context.Context, tenantID string, client *domain.Client) error {
	tenantID = strings.TrimSpace(tenantID)
	if client == nil {
		return domain.ErrInvalidArgument
	}
	clientID := strings.TrimSpace(client.Id)
	if tenantID == "" || clientID == "" || client.ManagedBy != "" {
		return domain.ErrInvalidArgument
	}
	client.Id = clientID
	data, err := json.Marshal(client)
	if err != nil {
		return err
	}
	result, err := legacyClientCreateScript.Eval(ctx, r.client, []string{
		clientsKey(tenantID), managedClientsKey(tenantID),
	}, clientID, data, `"managedBy":"`).Text()
	if err != nil {
		return err
	}
	switch result {
	case "stored":
		return nil
	case "protected":
		return domain.ErrManagedClientConflict
	default:
		return errStoredManagedClientContract
	}
}

// EnsureManagedAudience atomically creates, replays, or reconciles one owned managed client.
func (r *clientRepo) EnsureManagedAudience(
	ctx context.Context,
	tenantID string,
	client *domain.Client,
) (*domain.Client, bool, error) {
	if r == nil || r.client == nil || !validManagedAudienceClient(tenantID, client) {
		return nil, false, domain.ErrInvalidArgument
	}
	payload, err := json.Marshal(client)
	if err != nil {
		return nil, false, err
	}
	keys := []string{clientsKey(tenantID), managedClientsKey(tenantID)}
	for range 4 {
		values, ensureErr := managedClientEnsureScript.Eval(ctx, r.client, keys, client.Id, payload).StringSlice()
		if errors.Is(ensureErr, context.Canceled) || errors.Is(ensureErr, context.DeadlineExceeded) {
			return nil, false, ensureErr
		}
		if ensureErr != nil || len(values) != 2 {
			return nil, false, errStoredManagedClientContract
		}
		if values[0] == "shadow" {
			return nil, false, domain.ErrManagedClientConflict
		}
		if values[0] == "corrupt" || values[0] != "created" && values[0] != "existing" {
			return nil, false, errStoredManagedClientContract
		}
		stored, ok := decodeManagedAudienceClient(tenantID, values[1])
		if !ok {
			return nil, false, errStoredManagedClientContract
		}
		storedPayload, marshalErr := json.Marshal(stored)
		if marshalErr != nil || values[1] != string(storedPayload) {
			return nil, false, errStoredManagedClientContract
		}
		if sameManagedAudienceClient(stored, client) {
			if values[1] != string(payload) {
				return nil, false, errStoredManagedClientContract
			}
			return stored, values[0] == "created", nil
		}
		if values[0] == "created" || !sameManagedAudienceOwner(stored, client) {
			return nil, false, errStoredManagedClientContract
		}
		updated, updateErr := managedClientReconcileScript.Eval(
			ctx, r.client, keys, client.Id, values[1], payload,
		).StringSlice()
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
		reconciled, ok := decodeManagedAudienceClient(tenantID, updated[1])
		if !ok || !sameManagedAudienceClient(reconciled, client) {
			return nil, false, errStoredManagedClientContract
		}
		return reconciled, false, nil
	}
	return nil, false, domain.ErrManagedClientConflict
}

func (r *clientRepo) Get(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
	values, err := managedClientGetScript.Eval(ctx, r.client, []string{
		clientsKey(tenantID), managedClientsKey(tenantID),
	}, clientID).StringSlice()
	if err != nil {
		return nil, err
	}
	if len(values) != 2 {
		return nil, errStoredManagedClientContract
	}
	status, val := values[0], values[1]
	if status == "missing" {
		return nil, nil
	}
	if status == "corrupt" || status != "legacy" && status != "managed" {
		return nil, errStoredManagedClientContract
	}
	if status == "managed" {
		client, ok := decodeManagedAudienceClient(tenantID, val)
		if !ok {
			return nil, errStoredManagedClientContract
		}
		return client, nil
	}
	var client domain.Client
	if e := json.Unmarshal([]byte(val), &client); e != nil {
		return nil, e
	}
	if client.ManagedBy != "" {
		return nil, errStoredManagedClientContract
	}
	return &client, nil
}

func (r *clientRepo) List(ctx context.Context, tenantID string) ([]*domain.Client, error) {
	raw, err := managedClientListScript.Eval(ctx, r.client, []string{
		clientsKey(tenantID), managedClientsKey(tenantID),
	}).Text()
	if err != nil {
		return nil, err
	}
	var snapshot struct {
		Clients []string `json:"clients"`
		Markers []string `json:"markers"`
	}
	if json.Unmarshal([]byte(raw), &snapshot) != nil || len(snapshot.Clients)%2 != 0 || len(snapshot.Markers)%2 != 0 {
		return nil, errStoredManagedClientContract
	}
	vals, markers := alternatingMap(snapshot.Clients), alternatingMap(snapshot.Markers)
	out := make([]*domain.Client, 0, len(vals))
	managedSeen := make(map[string]struct{}, len(markers))
	for field, v := range vals {
		var c domain.Client
		if e := json.Unmarshal([]byte(v), &c); e != nil {
			return nil, e
		}
		if marker, marked := markers[field]; marked {
			managed, ok := decodeManagedAudienceClient(tenantID, v)
			if !ok || marker != v {
				return nil, errStoredManagedClientContract
			}
			c = *managed
			managedSeen[field] = struct{}{}
		} else if c.ManagedBy != "" {
			return nil, errStoredManagedClientContract
		}
		out = append(out, &c)
	}
	if len(managedSeen) != len(markers) {
		return nil, errStoredManagedClientContract
	}
	return out, nil
}

func clientsKey(tenantID string) string {
	return "clients:" + tenantID
}

func managedClientsKey(tenantID string) string {
	return "managedClients:" + tenantID
}

func alternatingMap(values []string) map[string]string {
	result := make(map[string]string, len(values)/2)
	for index := 0; index < len(values); index += 2 {
		result[values[index]] = values[index+1]
	}
	return result
}

func decodeManagedAudienceClient(tenantID, value string) (*domain.Client, bool) {
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var client domain.Client
	if decoder.Decode(&client) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validManagedAudienceClient(tenantID, &client) {
		return nil, false
	}
	return &client, true
}

func validManagedAudienceClient(tenantID string, client *domain.Client) bool {
	return canonicalTenantIdentity(tenantID) &&
		(domain.IsManagedCodeAdminAudience(tenantID, client) || domain.IsManagedWorkloadAccountAudience(tenantID, client)) &&
		scopepolicy.ValidCanonicalAudienceScopes(client.DefaultScopes)
}

func sameManagedAudienceClient(left, right *domain.Client) bool {
	return sameManagedAudienceOwner(left, right) &&
		slices.Equal(left.DefaultScopes, right.DefaultScopes)
}

func sameManagedAudienceOwner(left, right *domain.Client) bool {
	return left != nil && right != nil && validManagedAudienceClient(left.TenantId, left) &&
		validManagedAudienceClient(right.TenantId, right) && left.Id == right.Id &&
		left.TenantId == right.TenantId && left.ManagedBy == right.ManagedBy
}
