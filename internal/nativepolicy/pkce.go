package nativepolicy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"regexp"
)

var (
	ErrInvalidPKCE = errors.New("invalid native proof key")
	unreserved     = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

func ValidState(value string) bool { return unreserved.MatchString(value) }

func ValidS256Challenge(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func S256Challenge(verifier string) (string, error) {
	if !unreserved.MatchString(verifier) {
		return "", ErrInvalidPKCE
	}
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func VerifyS256(verifier, challenge string) bool {
	if !ValidS256Challenge(challenge) {
		return false
	}
	computed, err := S256Challenge(verifier)
	return err == nil && subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
