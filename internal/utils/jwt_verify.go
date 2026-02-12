package utils

import (
	"crypto/rsa"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ValidateRS256 validates an RS256 JWT using a provided RSA public key.
func ValidateRS256(tokenString string, pub *rsa.PublicKey, issuer string, audience string) (jwt.MapClaims, error) {
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return nil, errors.New("invalid token")
	}
	if pub == nil {
		return nil, errors.New("missing public key")
	}
	parsed, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("invalid alg")
		}
		return pub, nil
	})
	if err != nil || !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil || exp.Time.Before(time.Now()) {
		return nil, errors.New("invalid token")
	}
	if issuer != "" {
		if iss, _ := claims["iss"].(string); iss != issuer {
			return nil, errors.New("invalid issuer")
		}
	}
	if audience != "" {
		audRaw, exists := claims["aud"]
		if !exists {
			return nil, errors.New("invalid audience")
		}
		switch aud := audRaw.(type) {
		case string:
			if aud != audience {
				return nil, errors.New("invalid audience")
			}
		case []interface{}:
			found := false
			for _, v := range aud {
				if s, ok := v.(string); ok && s == audience {
					found = true
					break
				}
			}
			if !found {
				return nil, errors.New("invalid audience")
			}
		case []string:
			found := false
			for _, v := range aud {
				if v == audience {
					found = true
					break
				}
			}
			if !found {
				return nil, errors.New("invalid audience")
			}
		default:
			return nil, errors.New("invalid audience")
		}
	}
	return claims, nil
}
