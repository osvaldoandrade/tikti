package saml

import (
	"context"
	"errors"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vmihailenco/msgpack/v5"

	rkeys "github.com/osvaldoandrade/tikti/internal/redis"
)

// Compile-time interface compliance check.
var _ Store = (*RedisStore)(nil)

// luaConsumeRequest atomically GETs and DELetes a request record.
// Returns nil when the key does not exist, so exactly one consumer wins.
const luaConsumeRequest = `
local v = redis.call('GET', KEYS[1])
if not v then return nil end
redis.call('DEL', KEYS[1])
return v
`

var consumeRequestScript = redis.NewScript(luaConsumeRequest)

// RedisStore implements Store using Redis with Lua-script atomics and
// msgpack-encoded values.
type RedisStore struct {
	rdb *redis.Client
}

// NewRedisStore returns a Store backed by the given Redis client.
func NewRedisStore(rdb *redis.Client) *RedisStore {
	return &RedisStore{rdb: rdb}
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

// PutRequest stores a pending AuthnRequest with NX semantics (fail if the ID
// already exists) and a 300-second TTL.
func (s *RedisStore) PutRequest(ctx context.Context, rec RequestRecord) error {
	data, err := msgpack.Marshal(rec)
	if err != nil {
		return err
	}
	key := rkeys.SAMLRequestPrefix + rec.ID
	ok, err := s.rdb.SetNX(ctx, key, data, 300*time.Second).Result()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("saml: request ID already exists")
	}
	return nil
}

// ConsumeRequest atomically retrieves and deletes a pending request. The
// second return value is false when no record exists for the given ID.
func (s *RedisStore) ConsumeRequest(ctx context.Context, id string) (RequestRecord, bool, error) {
	key := rkeys.SAMLRequestPrefix + id
	raw, err := consumeRequestScript.Run(ctx, s.rdb, []string{key}).Text()
	if errors.Is(err, redis.Nil) {
		return RequestRecord{}, false, nil
	}
	if err != nil {
		return RequestRecord{}, false, err
	}
	if len(raw) == 0 {
		return RequestRecord{}, false, nil
	}
	var rec RequestRecord
	if err := msgpack.Unmarshal([]byte(raw), &rec); err != nil {
		return RequestRecord{}, false, err
	}
	return rec, true, nil
}

// ---------------------------------------------------------------------------
// IdPs
// ---------------------------------------------------------------------------

// PutIdP stores IdP trust material with a 24-hour TTL.
func (s *RedisStore) PutIdP(ctx context.Context, rec IdPRecord) error {
	data, err := msgpack.Marshal(rec)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, rkeys.SAMLIdPPrefix+rec.TenantID, data, 86400*time.Second).Err()
}

// GetIdP retrieves IdP trust material for a tenant. Returns ErrIdPNotFound
// when the key does not exist.
func (s *RedisStore) GetIdP(ctx context.Context, tid string) (IdPRecord, error) {
	raw, err := s.rdb.Get(ctx, rkeys.SAMLIdPPrefix+tid).Bytes()
	if errors.Is(err, redis.Nil) {
		return IdPRecord{}, ErrIdPNotFound
	}
	if err != nil {
		return IdPRecord{}, err
	}
	var rec IdPRecord
	if err := msgpack.Unmarshal(raw, &rec); err != nil {
		return IdPRecord{}, err
	}
	return rec, nil
}

// ListIdPs returns all stored IdP records using SCAN to avoid blocking.
func (s *RedisStore) ListIdPs(ctx context.Context) ([]IdPRecord, error) {
	var records []IdPRecord
	var cursor uint64
	pattern := rkeys.SAMLIdPPrefix + "*"
	for {
		keys, next, err := s.rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, err
		}
		if len(keys) > 0 {
			vals, err := s.rdb.MGet(ctx, keys...).Result()
			if err != nil {
				return nil, err
			}
			for _, v := range vals {
				str, ok := v.(string)
				if !ok || len(str) == 0 {
					continue
				}
				var rec IdPRecord
				if err := msgpack.Unmarshal([]byte(str), &rec); err != nil {
					return nil, err
				}
				records = append(records, rec)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return records, nil
}

// DeleteIdP removes the IdP record for the given tenant.
func (s *RedisStore) DeleteIdP(ctx context.Context, tid string) error {
	return s.rdb.Del(ctx, rkeys.SAMLIdPPrefix+tid).Err()
}

// ---------------------------------------------------------------------------
// Session indexes
// ---------------------------------------------------------------------------

// PutIndex stores a session index with a TTL derived from NotOnOrAfter.
func (s *RedisStore) PutIndex(ctx context.Context, nameID string, rec IndexRecord) error {
	data, err := msgpack.Marshal(rec)
	if err != nil {
		return err
	}
	ttl := time.Until(rec.NotOnOrAfter)
	if ttl <= 0 {
		ttl = time.Second // floor to avoid non-positive TTL
	}
	return s.rdb.Set(ctx, rkeys.SAMLIndexPrefix+nameID, data, ttl).Err()
}

// GetIndex retrieves the session index for a NameID.
func (s *RedisStore) GetIndex(ctx context.Context, nameID string) (IndexRecord, error) {
	raw, err := s.rdb.Get(ctx, rkeys.SAMLIndexPrefix+nameID).Bytes()
	if errors.Is(err, redis.Nil) {
		return IndexRecord{}, errors.New("saml: index not found")
	}
	if err != nil {
		return IndexRecord{}, err
	}
	var rec IndexRecord
	if err := msgpack.Unmarshal(raw, &rec); err != nil {
		return IndexRecord{}, err
	}
	return rec, nil
}

// DeleteIndex removes the session index for a NameID.
func (s *RedisStore) DeleteIndex(ctx context.Context, nameID string) error {
	return s.rdb.Del(ctx, rkeys.SAMLIndexPrefix+nameID).Err()
}

// ---------------------------------------------------------------------------
// Replay guard
// ---------------------------------------------------------------------------

// MarkSeen records an assertion ID to prevent replay. Returns true if the
// assertion was not previously seen (SETNX succeeded), false otherwise.
func (s *RedisStore) MarkSeen(ctx context.Context, assertionID string, ttl time.Duration) (bool, error) {
	return s.rdb.SetNX(ctx, rkeys.SAMLSeenPrefix+assertionID, 1, ttl).Result()
}

// ---------------------------------------------------------------------------
// Domain discovery
// ---------------------------------------------------------------------------

// PutDomain maps an email domain to a tenant ID.
func (s *RedisStore) PutDomain(ctx context.Context, domain, tid string) error {
	return s.rdb.Set(ctx, rkeys.SAMLDomainPrefix+domain, tid, 0).Err()
}

// GetDomain retrieves the tenant ID for an email domain.
func (s *RedisStore) GetDomain(ctx context.Context, domain string) (string, error) {
	val, err := s.rdb.Get(ctx, rkeys.SAMLDomainPrefix+domain).Result()
	if errors.Is(err, redis.Nil) {
		return "", errors.New("saml: domain not found")
	}
	return val, err
}

// DeleteDomain removes a domain→tenant mapping.
func (s *RedisStore) DeleteDomain(ctx context.Context, domain string) error {
	return s.rdb.Del(ctx, rkeys.SAMLDomainPrefix+domain).Err()
}
