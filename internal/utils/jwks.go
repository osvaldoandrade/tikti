package utils

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func BuildJWKS(key *rsa.PrivateKey, kid string) (*JWKS, error) {
	if strings.TrimSpace(kid) == "" {
		kid = "tikti-local-1"
	}
	if key == nil {
		return &JWKS{Keys: []JWK{}}, nil
	}
	pub := key.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	jwk := JWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   n,
		E:   e,
	}
	return &JWKS{Keys: []JWK{jwk}}, nil
}

func (j *JWKS) Marshal() ([]byte, error) {
	return json.Marshal(j)
}
