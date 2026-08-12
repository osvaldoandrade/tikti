package repository

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	exactMembershipPageTokenVersion = 1
	exactMembershipPageTokenMaxSize = 512
	exactMembershipPageTokenDomain  = "tikti-membership-page-v1\x00"
)

var exactMembershipPageTokenFields = fields("v", "tenant", "digest", "after", "pageSize")

type exactMembershipPageToken struct {
	Version  int    `json:"v"`
	Tenant   string `json:"tenant"`
	Digest   string `json:"digest"`
	After    string `json:"after"`
	PageSize int    `json:"pageSize"`
}

type exactMembershipPageTokenCodec struct {
	key []byte
}

func newExactMembershipPageTokenCodec(key []byte) (*exactMembershipPageTokenCodec, error) {
	if len(key) < sha256.Size {
		return nil, domain.ErrInvalidArgument
	}
	return &exactMembershipPageTokenCodec{key: append([]byte(nil), key...)}, nil
}

func (c *exactMembershipPageTokenCodec) encode(value exactMembershipPageToken) (string, error) {
	if c == nil || len(c.key) < sha256.Size || !validExactMembershipPageToken(value) {
		return "", domain.ErrInvalidArgument
	}
	payload, _ := json.Marshal(value)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	encodedMAC := base64.RawURLEncoding.EncodeToString(c.mac(payload))
	result := encodedPayload + "." + encodedMAC
	if len(result) > exactMembershipPageTokenMaxSize {
		return "", domain.ErrInvalidArgument
	}
	return result, nil
}

func (c *exactMembershipPageTokenCodec) decode(encoded, tenantID string, pageSize int) (*exactMembershipPageToken, error) {
	if encoded == "" {
		return nil, nil
	}
	if c == nil || len(c.key) < sha256.Size || len(encoded) > exactMembershipPageTokenMaxSize {
		return nil, domain.ErrInvalidArgument
	}
	payloadPart, macPart, ok := strings.Cut(encoded, ".")
	if !ok || payloadPart == "" || macPart == "" || strings.Contains(macPart, ".") {
		return nil, domain.ErrInvalidArgument
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(payloadPart)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != payloadPart {
		return nil, domain.ErrInvalidArgument
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(macPart)
	if err != nil || len(signature) != sha256.Size || base64.RawURLEncoding.EncodeToString(signature) != macPart || !hmac.Equal(signature, c.mac(payload)) {
		return nil, domain.ErrInvalidArgument
	}
	var token exactMembershipPageToken
	if !decodeExactObject(string(payload), exactMembershipPageTokenFields, &token) {
		return nil, domain.ErrInvalidArgument
	}
	canonical, _ := json.Marshal(token)
	if !bytes.Equal(canonical, payload) || !validExactMembershipPageToken(token) || token.Tenant != tenantID || token.PageSize != pageSize {
		return nil, domain.ErrInvalidArgument
	}
	return &token, nil
}

func (c *exactMembershipPageTokenCodec) mac(payload []byte) []byte {
	digest := hmac.New(sha256.New, c.key)
	_, _ = digest.Write([]byte(exactMembershipPageTokenDomain))
	_, _ = digest.Write(payload)
	return digest.Sum(nil)
}

func validExactMembershipPageToken(value exactMembershipPageToken) bool {
	return value.Version == exactMembershipPageTokenVersion && canonicalTenantIdentity(value.Tenant) &&
		validMembershipSnapshotDigest(value.Digest) && canonicalUserIdentity(value.After) &&
		value.PageSize >= 1 && value.PageSize <= exactMembershipListPageMax
}

func validMembershipSnapshotDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}
