package repository

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	exactClientPayloadLimit = 16 << 10
	exactClientListLimit    = 500
	exactClientsV2Prefix    = "clients:v2:"
	bcryptBase64Alphabet    = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// Direct EVAL is intentional. It keeps HLEN and HGETALL in one Redis turn and
// avoids the EVALSHA cache-miss incompatibility documented for Kvrocks 2.7.
const luaListExactClientsV2 = `
local count = redis.call('HLEN', KEYS[1])
if count > tonumber(ARGV[1]) then return {0} end
local values = redis.call('HGETALL', KEYS[1])
local result = {1}
for index = 1, #values do
  if index % 2 == 1 and string.len(values[index]) > 128 then
    return {-2}
  end
  if index % 2 == 0 and string.len(values[index]) > tonumber(ARGV[2]) then
    return {-1}
  end
  result[#result + 1] = values[index]
end
return result
`

// ExactClientReader exposes only fail-closed, credential-free v2 reads. It is
// deliberately separate from the permissive legacy ClientRepository writer.
type ExactClientReader interface {
	GetExact(ctx context.Context, tenantID, clientID string) (*domain.ClientIdentity, error)
	ListExact(ctx context.Context, tenantID string) ([]*domain.ClientIdentity, error)
}

type exactClientReader struct {
	client  *redis.Client
	tenants ExactTenantRepository
}

type storedExactClient struct {
	ClientId          string              `json:"clientId"`
	TenantId          string              `json:"tenantId"`
	SecretHash        string              `json:"secretHash"`
	Type              domain.ClientType   `json:"type"`
	AllowedGrantTypes []string            `json:"allowedGrantTypes"`
	DefaultScopes     []string            `json:"defaultScopes"`
	Status            domain.ClientStatus `json:"status"`
}

var (
	errStoredExactClientContract = errors.New("stored exact client contract mismatch")
	exactClientFields            = fields("clientId", "tenantId", "secretHash", "type", "allowedGrantTypes", "defaultScopes", "status")
	bcryptBase64                 = base64.NewEncoding(bcryptBase64Alphabet).WithPadding(base64.NoPadding).Strict()
)

func NewExactClientReader(client *redis.Client, tenants ExactTenantRepository) ExactClientReader {
	return &exactClientReader{client: client, tenants: tenants}
}

func (r *exactClientReader) GetExact(ctx context.Context, tenantID, clientID string) (*domain.ClientIdentity, error) {
	if !canonicalTenantIdentity(tenantID) {
		return nil, domain.ErrInvalidTenant
	}
	if !canonicalClientIdentity(clientID) {
		return nil, domain.ErrInvalidArgument
	}
	if !r.exactActiveTenant(ctx, tenantID) {
		return nil, errStoredExactClientContract
	}
	value, err := r.client.HGet(ctx, exactClientsV2Key(tenantID), clientID).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, errStoredExactClientContract
	}
	return projectExactClient(clientID, tenantID, value)
}

func (r *exactClientReader) ListExact(ctx context.Context, tenantID string) ([]*domain.ClientIdentity, error) {
	if !canonicalTenantIdentity(tenantID) {
		return nil, domain.ErrInvalidTenant
	}
	if !r.exactActiveTenant(ctx, tenantID) {
		return nil, errStoredExactClientContract
	}
	result, err := r.client.Eval(ctx, luaListExactClientsV2, []string{exactClientsV2Key(tenantID)}, exactClientListLimit, exactClientPayloadLimit).Result()
	if err != nil {
		return nil, errStoredExactClientContract
	}
	values, ok := exactClientListResult(result)
	if !ok {
		return nil, errStoredExactClientContract
	}
	clients := make([]*domain.ClientIdentity, 0, len(values)/2)
	for index := 0; index < len(values); index += 2 {
		clientID, fieldOK := redisResultString(values[index])
		value, valueOK := redisResultString(values[index+1])
		if !fieldOK || !valueOK {
			return nil, errStoredExactClientContract
		}
		client, readErr := projectExactClient(clientID, tenantID, value)
		if readErr != nil {
			return nil, errStoredExactClientContract
		}
		clients = append(clients, client)
	}
	sort.Slice(clients, func(left, right int) bool { return clients[left].ClientId < clients[right].ClientId })
	return clients, nil
}

func (r *exactClientReader) exactActiveTenant(ctx context.Context, tenantID string) bool {
	if r == nil || r.client == nil || r.tenants == nil {
		return false
	}
	tenant, err := r.tenants.GetExact(ctx, tenantID)
	return err == nil && tenant != nil && tenant.Id == tenantID && tenant.Status == domain.TenantStatusActive
}

func exactClientListResult(result any) ([]any, bool) {
	values, ok := result.([]any)
	if !ok || len(values) < 1 || (len(values)-1)%2 != 0 {
		return nil, false
	}
	marker, ok := values[0].(int64)
	if !ok || marker != 1 {
		return nil, false
	}
	return values[1:], true
}

func redisResultString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case []byte:
		return string(typed), true
	default:
		return "", false
	}
}

func projectExactClient(field, tenantID, value string) (*domain.ClientIdentity, error) {
	client, ok := decodeExactClient(value)
	if !ok || client.ClientId != field || client.TenantId != tenantID ||
		!canonicalClientIdentity(client.ClientId) || !canonicalTenantIdentity(client.TenantId) ||
		!validExactClientSecret(client.Type, client.SecretHash) ||
		!validExactClientGrantTypes(client.AllowedGrantTypes) ||
		!validExactClientScopes(client.DefaultScopes) || !validExactClientStatus(client.Status) {
		return nil, errStoredExactClientContract
	}
	return &domain.ClientIdentity{
		ClientId: client.ClientId, TenantId: client.TenantId, Type: client.Type,
		AllowedGrantTypes: append([]string{}, client.AllowedGrantTypes...),
		DefaultScopes:     append([]string{}, client.DefaultScopes...), Status: client.Status,
	}, nil
}

func decodeExactClient(value string) (storedExactClient, bool) {
	var client storedExactClient
	if len(value) < 1 || len(value) > exactClientPayloadLimit || !validJSONUnicode(value) {
		return client, false
	}
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return client, false
	}
	seen := make(map[string]struct{}, len(exactClientFields))
	for decoder.More() {
		field, tokenErr := decoder.Token()
		name, stringField := field.(string)
		if tokenErr != nil || !stringField {
			return client, false
		}
		if _, allowed := exactClientFields[name]; !allowed {
			return client, false
		}
		if _, duplicate := seen[name]; duplicate {
			return client, false
		}
		seen[name] = struct{}{}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return client, false
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != len(exactClientFields) {
		return client, false
	}
	if _, err = decoder.Token(); err != io.EOF || json.Unmarshal([]byte(value), &client) != nil {
		return client, false
	}
	return client, true
}

func validExactClientSecret(clientType domain.ClientType, hash string) bool {
	switch clientType {
	case domain.ClientTypePublic:
		return hash == ""
	case domain.ClientTypeService, domain.ClientTypeConfidential:
		if len(hash) != 60 || hash[6] != '$' || hash[:4] != "$2a$" && hash[:4] != "$2b$" && hash[:4] != "$2y$" {
			return false
		}
		for _, character := range []byte(hash[7:]) {
			if !strings.ContainsRune(bcryptBase64Alphabet, rune(character)) {
				return false
			}
		}
		salt, err := bcryptBase64.DecodeString(hash[7:29])
		if err != nil || len(salt) != 16 {
			return false
		}
		digest, err := bcryptBase64.DecodeString(hash[29:])
		if err != nil || len(digest) != 23 {
			return false
		}
		cost, err := bcrypt.Cost([]byte(hash))
		return err == nil && cost >= 10 && cost <= 14
	default:
		return false
	}
}

func validExactClientGrantTypes(values []string) bool {
	return len(values) == 1 && values[0] == string(domain.GrantTypeTokenExchange)
}

func validExactClientScopes(values []string) bool {
	if values == nil || len(values) > exactClientListLimit {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(value) < 1 || len(value) > 128 {
			return false
		}
		for _, character := range []byte(value) {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/*-", rune(character)) {
				return false
			}
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validExactClientStatus(status domain.ClientStatus) bool {
	return status == domain.ClientStatusActive || status == domain.ClientStatusInactive
}

func canonicalClientIdentity(value string) bool {
	if len(value) < 1 || len(value) > 128 || !clientIdentityEdge(value[0]) || !clientIdentityEdge(value[len(value)-1]) {
		return false
	}
	for _, character := range []byte(value) {
		if !clientIdentityEdge(character) && !strings.ContainsRune("._:-", rune(character)) {
			return false
		}
	}
	return true
}

func clientIdentityEdge(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func exactClientsV2Key(tenantID string) string {
	return exactClientsV2Prefix + tenantID
}
