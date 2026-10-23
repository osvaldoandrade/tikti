package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/internal/workloadidentity"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// This boundary test uses a real signed projected JWT and the real JWKS
// verifier. The API callback is a current-binding test double; authoritative
// Kubernetes owner-chain/ServicesSync proofs live in their owning repositories.
func TestAIUnexpiredProjectedTokenRequiresCurrentBindingForWorkloadAndDelegated(t *testing.T) {
	for _, delegated := range []bool{false, true} {
		kind := "Workload"
		if delegated {
			kind = "Delegated"
		}
		for _, change := range []string{"service-and-sa", "sa", "pod", "expired-observation", "tenant"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				users, userRequest, original, _, tenant := aiUserFixture(t)
				key, _ := workloadTestKey(t)
				public, err := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "cluster-test", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())}}})
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "jwks.json")
				if err := os.WriteFile(path, public, 0600); err != nil {
					t.Fatal(err)
				}
				verifier, err := workloadidentity.NewJWKSVerifier("https://cluster.example", "tikti-workload-exchange", "file://"+path, &http.Client{Timeout: time.Second}, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				verifier.WithClusterRef("cluster-1")
				source, sa, pod, current := "service-1", "sa-1", "pod-1", true
				authority := aiAuthorityFunc(func(ctx context.Context, raw string) (aigateway.Principal, error) {
					p, err := original.Authorize(ctx, raw)
					if err != nil {
						return p, err
					}
					if w := p.Workload; w != nil {
						if !current || w.ServiceAccountUID != sa || w.PodUID != pod {
							return aigateway.Principal{}, errors.New("current workload observation unavailable")
						}
						w.ServiceUID = source
						if p.PrincipalKind == "Workload" {
							p.Subject = "codefoundry:service:" + source
						}
					}
					return p, nil
				})
				users.aiGateway.authority = authority
				userToken, err := users.TokenExchange(t.Context(), userRequest)
				if err != nil {
					t.Fatal(err)
				}
				cfg := users.aiGateway.cfg
				service := NewWorkloadIdentityService(nil, verifier, "https://issuer", users.jwksPrivateKey, "kid", time.Hour, WithWorkloadAIGateway(cfg, authority, &topicTenantReader{tenant: tenant}, users)).(*workloadIdentityService)
				sign := func(saUID, podUID string) string {
					claims := jwt.MapClaims{"iss": "https://cluster.example", "sub": "system:serviceaccount:workload-tenant-1:worker", "aud": []string{"tikti-workload-exchange"}, "iat": time.Now().Add(-time.Second).Unix(), "nbf": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(90 * time.Second).Unix(), "kubernetes.io": map[string]any{"namespace": "workload-tenant-1", "serviceaccount": map[string]any{"name": "worker", "uid": saUID}, "pod": map[string]any{"name": "worker-pod", "uid": podUID}}}
					token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
					token.Header["kid"] = "cluster-test"
					raw, err := token.SignedString(key)
					if err != nil {
						t.Fatal(err)
					}
					return raw
				}
				request := domain.WorkloadTokenExchangeReq{SubjectToken: sign(sa, pod), SubjectTokenType: domain.WorkloadSubjectTokenType, Audience: aigateway.Audience, TenantID: tenant.Id, Scopes: []string{aigateway.InvokeScope}}
				if delegated {
					request.UserToken = userToken.AccessToken
				}
				issued, err := service.Exchange(t.Context(), request)
				if err != nil {
					t.Fatalf("current binding control: %v", err)
				}
				if _, err := users.ValidateAIAccessToken(t.Context(), issued.AccessToken); err != nil {
					t.Fatal(err)
				}
				switch change {
				case "service-and-sa":
					source, sa, pod = "replacement-service", "replacement-sa", "replacement-pod"
				case "sa":
					sa = "replacement-sa"
				case "pod":
					pod = "replacement-pod"
				case "expired-observation":
					current = false
				case "tenant":
					tenant.CreatedAt = tenant.CreatedAt.Add(time.Second)
				}
				if _, err := verifier.Verify(t.Context(), request.SubjectToken); err != nil {
					t.Fatalf("test token must remain cryptographically valid: %v", err)
				}
				if got, err := service.Exchange(t.Context(), request); err == nil || got != nil {
					t.Fatal("unexpired stale projected token acquired current identity")
				}
				if _, err := users.ValidateAIAccessToken(t.Context(), issued.AccessToken); err == nil {
					t.Fatal("issued token kept withdrawn current binding")
				}
				if change == "service-and-sa" || change == "sa" || change == "pod" {
					request.SubjectToken = sign(sa, pod)
					if got, err := service.Exchange(t.Context(), request); err != nil || got == nil {
						t.Fatalf("current replacement identity refused: %v", err)
					}
				}
			})
		}
	}
}
