// Package nativeauth implements the public-client authorization-code boundary
// used to carry an audited browser SAML session into a native application.
package nativeauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/nativepolicy"
)

var (
	ErrUnavailable  = errors.New("native authorization unavailable")
	ErrInvalidGrant = errors.New("invalid native authorization grant")
	principalID     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

const (
	RequestTTL    = 5 * time.Minute
	CodeTTL       = time.Minute
	maximumRecord = 128 << 10
)

type Request struct {
	ClientID          string `json:"clientId"`
	ClientFingerprint string `json:"clientFingerprint"`
	RedirectURI       string `json:"redirectUri"`
	State             string `json:"state"`
	Challenge         string `json:"challenge"`
	ExpiresAt         int64  `json:"expiresAt"`
}

// Grant retains authorization metadata only. The browser cookie, access token,
// plaintext authorization code and PKCE verifier are never persisted here.
type Grant struct {
	ClientID            string   `json:"clientId"`
	ClientFingerprint   string   `json:"clientFingerprint"`
	RedirectURI         string   `json:"redirectUri"`
	Challenge           string   `json:"challenge"`
	Subject             string   `json:"subject"`
	IdentityTenantID    string   `json:"identityTenantId"`
	IdentityFingerprint string   `json:"identityFingerprint"`
	TokenVersion        int64    `json:"tokenVersion"`
	ApprovedScopes      []string `json:"approvedScopes"`
	SessionExpiresAt    int64    `json:"sessionExpiresAt"`
	ExpiresAt           int64    `json:"expiresAt"`
}

type RequestSnapshot struct {
	Value Request
	raw   string
}

type GrantSnapshot struct {
	Value Grant
	raw   string
}

type Store struct {
	client *redis.Client
	now    func() time.Time
	random io.Reader
}

func NewStore(client *redis.Client, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{client: client, now: now, random: rand.Reader}
}

var readRecord = redis.NewScript(`
local size = redis.call("STRLEN", KEYS[1])
if size > tonumber(ARGV[1]) then return redis.error_reply("native record invalid") end
return redis.call("GET", KEYS[1])
`)

var consumeRecord = redis.NewScript(`
if redis.call("STRLEN", KEYS[1]) ~= string.len(ARGV[1]) then return 0 end
if redis.call("GET", KEYS[1]) ~= ARGV[1] then return 0 end
return redis.call("DEL", KEYS[1])
`)

func opaque(value string) bool { return nativepolicy.ValidS256Challenge(value) }

func fingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func stateKey(kind, value string) string {
	digest := sha256.Sum256([]byte(value))
	return "identity:v2:native:" + kind + ":" + hex.EncodeToString(digest[:])
}

func (r Request) valid() bool {
	return principalID.MatchString(r.ClientID) && fingerprint(r.ClientFingerprint) &&
		len(r.RedirectURI) > 0 && len(r.RedirectURI) <= 1024 && nativepolicy.ValidState(r.State) &&
		nativepolicy.ValidS256Challenge(r.Challenge) && r.ExpiresAt > 0
}

func (g Grant) valid() bool {
	if !principalID.MatchString(g.ClientID) || !fingerprint(g.ClientFingerprint) ||
		len(g.RedirectURI) < 1 || len(g.RedirectURI) > 1024 || !nativepolicy.ValidS256Challenge(g.Challenge) ||
		!principalID.MatchString(g.Subject) || !principalID.MatchString(g.IdentityTenantID) ||
		!fingerprint(g.IdentityFingerprint) || g.TokenVersion < 0 || g.ExpiresAt < 1 ||
		g.ExpiresAt > g.SessionExpiresAt || len(g.ApprovedScopes) < 1 || len(g.ApprovedScopes) > 500 {
		return false
	}
	seen := make(map[string]bool, len(g.ApprovedScopes))
	for _, scope := range g.ApprovedScopes {
		if !nativepolicy.ValidScope(scope) || seen[scope] {
			return false
		}
		seen[scope] = true
	}
	return true
}

func (s *Store) CreateRequest(ctx context.Context, value Request) (string, error) {
	if s == nil || s.client == nil {
		return "", ErrUnavailable
	}
	value.ExpiresAt = s.now().Add(RequestTTL).Unix()
	if !value.valid() {
		return "", ErrInvalidGrant
	}
	return s.put(ctx, "request", value, value.ExpiresAt)
}

func (s *Store) CreateCode(ctx context.Context, value Grant) (string, error) {
	if s == nil || s.client == nil {
		return "", ErrUnavailable
	}
	value.ExpiresAt = min(s.now().Add(CodeTTL).Unix(), value.SessionExpiresAt)
	if !value.valid() || value.ExpiresAt <= s.now().Unix() {
		return "", ErrInvalidGrant
	}
	return s.put(ctx, "code", value, value.ExpiresAt)
}

func (s *Store) put(ctx context.Context, kind string, value any, expiry int64) (string, error) {
	if s == nil || s.client == nil {
		return "", ErrUnavailable
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maximumRecord {
		return "", ErrUnavailable
	}
	remaining := time.Unix(expiry, 0).Sub(s.now())
	if remaining <= 0 {
		return "", ErrInvalidGrant
	}
	for attempt := 0; attempt < 3; attempt++ {
		var entropy [32]byte
		if _, err := io.ReadFull(s.random, entropy[:]); err != nil {
			return "", ErrUnavailable
		}
		id := base64.RawURLEncoding.EncodeToString(entropy[:])
		created, err := s.client.SetNX(ctx, stateKey(kind, id), encoded, remaining).Result()
		if err != nil {
			return "", ErrUnavailable
		}
		if created {
			return id, nil
		}
	}
	return "", ErrUnavailable
}

func (s *Store) Request(ctx context.Context, id string) (RequestSnapshot, error) {
	raw, err := s.read(ctx, "request", id)
	if err != nil {
		return RequestSnapshot{}, err
	}
	var value Request
	if decode(raw, &value) != nil || !value.valid() {
		return RequestSnapshot{}, ErrUnavailable
	}
	if value.ExpiresAt <= s.now().Unix() {
		return RequestSnapshot{}, ErrInvalidGrant
	}
	return RequestSnapshot{Value: value, raw: raw}, nil
}

func (s *Store) Code(ctx context.Context, code string) (GrantSnapshot, error) {
	raw, err := s.read(ctx, "code", code)
	if err != nil {
		return GrantSnapshot{}, err
	}
	var value Grant
	if decode(raw, &value) != nil || !value.valid() {
		return GrantSnapshot{}, ErrUnavailable
	}
	if value.ExpiresAt <= s.now().Unix() || value.SessionExpiresAt <= s.now().Unix() {
		return GrantSnapshot{}, ErrInvalidGrant
	}
	return GrantSnapshot{Value: value, raw: raw}, nil
}

func (s *Store) read(ctx context.Context, kind, id string) (string, error) {
	if !opaque(id) {
		return "", ErrInvalidGrant
	}
	if s == nil || s.client == nil {
		return "", ErrUnavailable
	}
	// Use EVAL directly: Kvrocks prefixes cache misses with ERR NOSCRIPT,
	// outside go-redis v8's automatic script-cache fallback recognition.
	raw, err := readRecord.Eval(ctx, s.client, []string{stateKey(kind, id)}, maximumRecord).Text()
	if errors.Is(err, redis.Nil) {
		return "", ErrInvalidGrant
	}
	if err != nil || len(raw) < 1 || len(raw) > maximumRecord {
		return "", ErrUnavailable
	}
	return raw, nil
}

func decode(raw string, target any) error {
	// Reject duplicate top-level fields as well as unknown fields. A record
	// must have one unambiguous meaning before it participates in a grant.
	fields := json.NewDecoder(bytes.NewBufferString(raw))
	start, err := fields.Token()
	if err != nil || start != json.Delim('{') {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for fields.More() {
		token, err := fields.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return ErrUnavailable
		}
		seen[key] = true
		var value json.RawMessage
		if fields.Decode(&value) != nil {
			return ErrUnavailable
		}
	}
	if end, err := fields.Token(); err != nil || end != json.Delim('}') {
		return ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) ConsumeRequest(ctx context.Context, id string, snapshot RequestSnapshot) (bool, error) {
	if s == nil || s.client == nil {
		return false, ErrUnavailable
	}
	encoded, err := json.Marshal(snapshot.Value)
	if err != nil || string(encoded) != snapshot.raw || snapshot.Value.ExpiresAt <= s.now().Unix() {
		return false, ErrInvalidGrant
	}
	return s.consume(ctx, "request", id, snapshot.raw)
}

func (s *Store) ConsumeCode(ctx context.Context, code string, snapshot GrantSnapshot) (bool, error) {
	if s == nil || s.client == nil {
		return false, ErrUnavailable
	}
	encoded, err := json.Marshal(snapshot.Value)
	if err != nil || string(encoded) != snapshot.raw || snapshot.Value.ExpiresAt <= s.now().Unix() {
		return false, ErrInvalidGrant
	}
	return s.consume(ctx, "code", code, snapshot.raw)
}

func (s *Store) consume(ctx context.Context, kind, id, raw string) (bool, error) {
	if !opaque(id) || len(raw) < 1 || len(raw) > maximumRecord {
		return false, ErrInvalidGrant
	}
	if s == nil || s.client == nil {
		return false, ErrUnavailable
	}
	consumed, err := consumeRecord.Eval(ctx, s.client, []string{stateKey(kind, id)}, raw).Int64()
	if err != nil {
		return false, ErrUnavailable
	}
	return consumed == 1, nil
}
