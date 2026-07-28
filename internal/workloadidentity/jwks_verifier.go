package workloadidentity

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	maxJWKSResponseBytes      = 1 << 20
	minimumRSAKeyBits         = 2048
	unknownKIDRefreshInterval = 30 * time.Second
)

type JWKSVerifier struct {
	issuer   string
	audience string
	jwksURL  *url.URL
	http     *http.Client
	cacheTTL time.Duration
	now      func() time.Time

	mu                    sync.Mutex
	keys                  map[string]*rsa.PublicKey
	expiresAt             time.Time
	nextUnknownKIDRefresh time.Time
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func NewJWKSVerifier(issuer, audience, rawJWKSURL string, client *http.Client, cacheTTL time.Duration) (*JWKSVerifier, error) {
	issuer = strings.TrimSpace(issuer)
	audience = strings.TrimSpace(audience)
	parsedURL, err := url.Parse(strings.TrimSpace(rawJWKSURL))
	if err != nil || issuer == "" || audience == "" || parsedURL.Host == "" || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") {
		return nil, fmt.Errorf("invalid workload identity verifier configuration")
	}
	if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, fmt.Errorf("invalid workload JWKS URL")
	}
	if parsedURL.Scheme == "http" && !isLocalHost(parsedURL.Hostname()) {
		return nil, fmt.Errorf("workload JWKS URL requires HTTPS outside loopback")
	}
	if client == nil || cacheTTL <= 0 {
		return nil, fmt.Errorf("workload verifier HTTP client and positive cache TTL are required")
	}
	httpClient := *client
	// A configured JWKS endpoint is an explicit trust boundary. Redirects could
	// otherwise downgrade HTTPS or cross that boundary to an unexpected host.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &JWKSVerifier{
		issuer: issuer, audience: audience, jwksURL: parsedURL, http: &httpClient,
		cacheTTL: cacheTTL, now: time.Now, keys: make(map[string]*rsa.PublicKey),
	}, nil
}

func (v *JWKSVerifier) Verify(ctx context.Context, subjectToken string) (domain.WorkloadSubject, error) {
	if len(subjectToken) == 0 || len(subjectToken) > 64<<10 {
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithTimeFunc(v.now),
	)
	claims := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(subjectToken, claims, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		if strings.TrimSpace(kid) == "" {
			return nil, domain.ErrWorkloadTokenInvalid
		}
		return v.keyFor(ctx, kid)
	})
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, domain.ErrWorkloadIdentityUnavailable) {
			return domain.WorkloadSubject{}, fmt.Errorf("%w: verify subject token: %v", domain.ErrWorkloadIdentityUnavailable, err)
		}
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	if token == nil || !token.Valid {
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	audiences, err := claims.GetAudience()
	if err != nil || len(audiences) != 1 || audiences[0] != v.audience {
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil || !expiresAt.After(v.now()) {
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	subject, err := validatedKubernetesSubject(claims)
	if err != nil {
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	return subject, nil
}

func (v *JWKSVerifier) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if now.Before(v.expiresAt) {
		if key := v.keys[kid]; key != nil {
			return key, nil
		}
		if now.Before(v.nextUnknownKIDRefresh) {
			return nil, domain.ErrWorkloadTokenInvalid
		}
	}
	if err := v.refreshLocked(ctx); err != nil {
		return nil, fmt.Errorf("%w: refresh workload JWKS: %v", domain.ErrWorkloadIdentityUnavailable, err)
	}
	key := v.keys[kid]
	if key == nil {
		return nil, domain.ErrWorkloadTokenInvalid
	}
	return key, nil
}

func (v *JWKSVerifier) refreshLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("workload JWKS returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxJWKSResponseBytes {
		return fmt.Errorf("workload JWKS response exceeds %d bytes", maxJWKSResponseBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var document jwksDocument
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("workload JWKS contains trailing data")
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, item := range document.Keys {
		if item.Kty != "RSA" || strings.TrimSpace(item.Kid) == "" || (item.Alg != "" && item.Alg != jwt.SigningMethodRS256.Alg()) || (item.Use != "" && item.Use != "sig") {
			continue
		}
		key, err := rsaKey(item.N, item.E)
		if err != nil {
			continue
		}
		if _, duplicate := keys[item.Kid]; duplicate {
			return fmt.Errorf("workload JWKS contains duplicate signing key id")
		}
		keys[item.Kid] = key
	}
	if len(keys) == 0 {
		return fmt.Errorf("workload JWKS has no usable signing keys")
	}
	v.keys = keys
	now := v.now()
	v.expiresAt = now.Add(v.cacheTTL)
	refreshInterval := unknownKIDRefreshInterval
	if v.cacheTTL < refreshInterval {
		refreshInterval = v.cacheTTL
	}
	v.nextUnknownKIDRefresh = now.Add(refreshInterval)
	return nil
}

func rsaKey(modulus, exponent string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil || len(nBytes) == 0 {
		return nil, fmt.Errorf("invalid RSA modulus")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(exponent)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	var exponentValue uint64
	for _, value := range eBytes {
		exponentValue = exponentValue<<8 + uint64(value)
	}
	if exponentValue < 3 || exponentValue > 1<<31-1 || exponentValue%2 == 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(exponentValue)}
	if key.N.BitLen() < minimumRSAKeyBits {
		return nil, fmt.Errorf("RSA modulus must be at least %d bits", minimumRSAKeyBits)
	}
	return key, nil
}

func validatedKubernetesSubject(claims jwt.MapClaims) (domain.WorkloadSubject, error) {
	subject, err := claims.GetSubject()
	if err != nil {
		return domain.WorkloadSubject{}, err
	}
	identity, valid := domain.ParseWorkloadSubject(subject)
	if !valid {
		return domain.WorkloadSubject{}, fmt.Errorf("invalid service account subject")
	}
	namespace, serviceAccount := kubernetesIdentityClaims(claims)
	if namespace == "" || serviceAccount == "" || namespace != identity.Namespace || serviceAccount != identity.ServiceAccount {
		return domain.WorkloadSubject{}, fmt.Errorf("kubernetes identity claims do not match subject")
	}
	return identity, nil
}

func kubernetesIdentityClaims(claims jwt.MapClaims) (string, string) {
	if raw, ok := claims["kubernetes.io"].(map[string]interface{}); ok {
		namespace, _ := raw["namespace"].(string)
		if serviceAccount, ok := raw["serviceaccount"].(map[string]interface{}); ok {
			name, _ := serviceAccount["name"].(string)
			return strings.TrimSpace(namespace), strings.TrimSpace(name)
		}
	}
	namespace, _ := claims["kubernetes.io/serviceaccount/namespace"].(string)
	serviceAccount, _ := claims["kubernetes.io/serviceaccount/service-account.name"].(string)
	return strings.TrimSpace(namespace), strings.TrimSpace(serviceAccount)
}

func isLocalHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
