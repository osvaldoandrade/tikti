package utils

import (
	"crypto/rsa"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// ParseRSAPrivateKey loads an RSA private key from PEM.
func ParseRSAPrivateKey(pem string) (*rsa.PrivateKey, error) {
	if pem == "" {
		return nil, errors.New("rsa private key missing")
	}
	return jwt.ParseRSAPrivateKeyFromPEM([]byte(pem))
}
