package utils

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ParseToken validates a JWT string, defaulting the secret when empty, and returns claims.
func ParseToken(tokenString, secret string) (jwt.MapClaims, error) {
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return nil, errors.New("invalid token")
	}
	if secret == "" {
		secret = "supersecret"
	}
	parsed, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
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
	return claims, nil
}
