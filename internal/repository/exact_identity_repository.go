package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// ExactTenantRepository provides fail-closed tenant reads without changing the
// permissive legacy repository contract.
type ExactTenantRepository interface {
	GetExact(ctx context.Context, tenantID string) (*domain.Tenant, error)
}

// ExactUserRepository provides fail-closed, password-free user reads without
// changing legacy lookup or migration behavior.
type ExactUserRepository interface {
	GetExact(ctx context.Context, userID string) (*domain.UserIdentity, error)
}

var (
	errStoredTenantContract = errors.New("stored tenant contract mismatch")
	errStoredUserContract   = errors.New("stored user contract mismatch")
	tenantFields            = fields("id", "slug", "name", "status", "createdAt")
	userFields              = fields("localId", "email", "password", "role", "status", "companyId", "tokenVersion", "createdAt", "authSource", "externalSubject")
)

func (r *tenantRepo) GetExact(ctx context.Context, tenantID string) (*domain.Tenant, error) {
	if !canonicalTenantIdentity(tenantID) {
		return nil, domain.ErrInvalidTenant
	}
	value, err := r.client.HGet(ctx, tenantsHash, tenantID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tenant domain.Tenant
	if value == "" || !decodeExactObject(value, tenantFields, &tenant) ||
		tenant.Id != tenantID || !canonicalTenantIdentity(tenant.Id) ||
		!canonicalTenantIdentity(tenant.Slug) || !validTenantName(tenant.Name) ||
		!validTenantStatus(tenant.Status) || tenant.CreatedAt.IsZero() {
		return nil, errStoredTenantContract
	}
	return &tenant, nil
}

func (r *redisRepo) GetExact(ctx context.Context, userID string) (*domain.UserIdentity, error) {
	if !canonicalUserIdentity(userID) {
		return nil, domain.ErrInvalidArgument
	}
	value, err := r.client.HGet(ctx, usersHashV2, userID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var user domain.User
	if value == "" || !decodeExactObject(value, userFields, &user) ||
		user.Id != userID || !canonicalUserIdentity(user.Id) ||
		!canonicalEmail(user.Email) || !validUserStatus(user.Status) ||
		user.CreatedAt.IsZero() || user.TokenVersion < 0 {
		return nil, errStoredUserContract
	}
	authSource, ok := exactAuthSource(user)
	if !ok {
		return nil, errStoredUserContract
	}
	indexedID, err := r.client.Get(ctx, userByEmailKeyNS+user.Email).Result()
	if err == redis.Nil || err == nil && indexedID != userID {
		return nil, errStoredUserContract
	}
	if err != nil {
		return nil, err
	}
	return &domain.UserIdentity{
		Id:         user.Id,
		Email:      user.Email,
		Status:     user.Status,
		AuthSource: authSource,
		CreatedAt:  user.CreatedAt,
	}, nil
}

func exactAuthSource(user domain.User) (domain.AuthSource, bool) {
	switch user.AuthSource {
	case domain.AuthSourcePassword:
		return user.AuthSource, user.Password != ""
	case "":
		return domain.AuthSourcePassword, user.Password != ""
	case domain.AuthSourceSAML:
		return user.AuthSource, validExternalSubject(user.ExternalSubject)
	default:
		return "", false
	}
}

func validTenantStatus(status domain.TenantStatus) bool {
	return status == domain.TenantStatusActive || status == domain.TenantStatusDisabled
}

func validUserStatus(status domain.UserStatus) bool {
	return status == domain.UserStatusActive || status == domain.UserStatusInactive || status == domain.UserStatusSuspended
}

func canonicalTenantIdentity(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func canonicalUserIdentity(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", rune(value[index])) {
			return false
		}
	}
	return true
}

func canonicalEmail(value string) bool {
	if len(value) < 3 || len(value) > 254 || strings.Count(value, "@") != 1 {
		return false
	}
	at := strings.IndexByte(value, '@')
	if at == 0 || at == len(value)-1 {
		return false
	}
	for index := range len(value) {
		if value[index] < '!' || value[index] > '~' {
			return false
		}
	}
	return true
}

func validTenantName(value string) bool {
	return validIdentityText(value, 128)
}

func validExternalSubject(value string) bool {
	return len(value) <= 512 && validIdentityText(value, 512)
}

func validIdentityText(value string, maxRunes int) bool {
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > maxRunes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func fields(names ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(names))
	for _, name := range names {
		result[name] = struct{}{}
	}
	return result
}

func decodeExactObject(value string, allowed map[string]struct{}, target any) bool {
	if !validJSONUnicode(value) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}
	seen := make(map[string]struct{}, len(allowed))
	for decoder.More() {
		field, err := decoder.Token()
		name, ok := field.(string)
		if err != nil || !ok {
			return false
		}
		if _, ok = allowed[name]; !ok {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		seen[name] = struct{}{}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return false
	}
	if _, err = decoder.Token(); err != io.EOF {
		return false
	}
	return json.Unmarshal([]byte(value), target) == nil
}

func validJSONUnicode(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	inString := false
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			index++
			if index >= len(value) {
				return false
			}
			if value[index] != 'u' {
				continue
			}
			unit, ok := jsonHexUnit(value, index+1)
			if !ok || unit >= 0xdc00 && unit <= 0xdfff {
				return false
			}
			index += 4
			if unit < 0xd800 || unit > 0xdbff {
				continue
			}
			if index+6 >= len(value) || value[index+1] != '\\' || value[index+2] != 'u' {
				return false
			}
			low, ok := jsonHexUnit(value, index+3)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			index += 6
		}
	}
	return true
}

func jsonHexUnit(value string, offset int) (uint64, bool) {
	if offset+4 > len(value) {
		return 0, false
	}
	unit, err := strconv.ParseUint(value[offset:offset+4], 16, 16)
	return unit, err == nil
}
