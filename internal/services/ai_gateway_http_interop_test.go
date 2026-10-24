//go:build cfp070identityinterop

package services

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/internal/workloadidentity"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const interopAgentToken = "synthetic-agent-identity-http-contract"

type aiHTTPPeer struct {
	url    string
	client *http.Client
	write  *json.Encoder
	read   *json.Decoder
}

func startAIHTTPPeer(t *testing.T, jwks json.RawMessage, epoch string) (*aiHTTPPeer, *x509.CertPool) {
	t.Helper()
	binary := os.Getenv("CFP070_API_IDENTITY_PEER_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("explicit compiled API test peer is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	command := exec.CommandContext(ctx, binary, "-test.run=^TestAIIdentityHTTPPeer$", "-test.timeout=40s")
	command.Env = append(os.Environ(), "CFP070_IDENTITY_PEER=1")
	stdin, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	command.ExtraFiles = []*os.File{writer}
	// Production request logs contain no bearer material, but the peer's stdout
	// is deliberately not the fixture protocol or a token-bearing test failure.
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		cancel()
		t.Fatal(err)
	}
	_ = writer.Close()
	p := &aiHTTPPeer{write: json.NewEncoder(stdin), read: json.NewDecoder(reader)}
	t.Cleanup(func() {
		_ = p.write.Encode(map[string]string{"operation": "close"})
		_ = stdin.Close()
		if err := command.Wait(); err != nil {
			t.Errorf("API fixture peer did not exit successfully: %v", err)
		}
		_ = reader.Close()
		cancel()
	})
	if err := p.write.Encode(map[string]any{"operation": "start", "jwks": jwks, "tenantEpoch": epoch}); err != nil {
		t.Fatal(err)
	}
	var initial struct {
		URL         string `json:"url"`
		Certificate []byte `json:"certificate"`
	}
	if err := p.read.Decode(&initial); err != nil {
		t.Fatalf("API peer handshake failed: %v", err)
	}
	u, err := url.Parse(initial.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" {
		t.Fatal("API peer must be HTTPS loopback")
	}
	cert, err := x509.ParseCertificate(initial.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	p.url = initial.URL
	p.client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}
	t.Cleanup(p.client.CloseIdleConnections)
	return p, pool
}

func (p *aiHTTPPeer) control(t *testing.T, operation, uid, epoch string) map[string]any {
	t.Helper()
	if err := p.write.Encode(map[string]string{"operation": operation, "serviceUID": uid, "tenantEpoch": epoch}); err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if err := p.read.Decode(&response); err != nil {
		t.Fatalf("API fixture control failed: %v", err)
	}
	return response
}

func (p *aiHTTPPeer) sync(t *testing.T, reports ...map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"agentId": "contract-agent", "reports": reports})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, p.url+"/internal/v1/agent/services:sync", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+interopAgentToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var decoded struct {
		Services []map[string]any `json:"services"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&decoded) != nil || len(decoded.Services) != 1 {
		t.Fatalf("real ServicesSync HTTP failed, status %d", response.StatusCode)
	}
	return decoded.Services[0]
}

func interopIdentityReport(t *testing.T, desired map[string]any, sa, pod string) map[string]any {
	t.Helper()
	c, ok := desired["workloadIdentityContext"].(map[string]any)
	if !ok {
		t.Fatal("current desired identity context missing")
	}
	sourceUID, ok := desired["sourceUid"].(string)
	if !ok || sourceUID == "" {
		t.Fatal("canonical desired sourceUid missing")
	}
	return map[string]any{
		"name": desired["name"], "namespace": desired["namespace"], "tenantId": desired["tenantId"],
		"generation": 1, "observedGeneration": desired["generation"], "phase": "Provisioned", "ready": true,
		"sourceServiceUID": sourceUID, "serviceAccountId": "system:serviceaccount:workload-tenant-1:worker",
		"workloadIdentity": map[string]any{
			"schemaVersion": "workload-identity/v1", "serviceUID": "local-" + sourceUID,
			"sourceServiceUID": sourceUID, "sourceServiceGeneration": desired["generation"], "observedGeneration": 1,
			"tenantId": "tenant-1", "tenantEpoch": c["tenantEpoch"], "clusterRef": "cluster-1", "issuer": "https://cluster.example",
			"namespace": "workload-tenant-1", "serviceAccount": "worker", "serviceAccountUID": sa, "podUIDs": []string{pod},
			"observedAt": time.Now().UTC().Format(time.RFC3339Nano), "contextObservedAt": c["observedAt"],
		},
	}
}

// This explicit interop test replaces the old callback double with the real
// Tikti HTTP authority Client and a separately compiled API application. Tenant,
// user/client repositories and native producer observations remain synthetic.
// It does not claim the Tikti HTTP ingress or native Kubernetes producer path.
func TestAIHTTPInteropProjectedLifetimes(t *testing.T) {
	// The production client validates TLS normally. Trust only the test peer's
	// certificate via the documented process-local fallback pool, with no
	// InsecureSkipVerify or production constructor/transport modification.
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1")
	rootSet := false
	for _, kind := range []string{"Workload", "Delegated"} {
		for _, change := range []string{"service", "tenant", "expired-context"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				users, userRequest, signerFixture, _, tenant := aiUserFixture(t)
				epoch, err := users.aiGateway.tenant(t.Context(), tenant.Id, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				key, _ := workloadTestKey(t)
				jwks := func(n *big.Int, e int, kid string) json.RawMessage {
					raw, err := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(n.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(e)).Bytes())}}})
					if err != nil {
						t.Fatal(err)
					}
					return raw
				}
				peer, pool := startAIHTTPPeer(t, jwks(signerFixture.key.N, signerFixture.key.E, "kid"), epoch)
				if !rootSet {
					x509.SetFallbackRoots(pool)
					rootSet = true
				}
				authority, err := aigateway.NewClient(peer.url+aigateway.AuthorityPath, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				users.aiGateway.authority = authority
				jwksPath := filepath.Join(t.TempDir(), "projected-public-jwks.json")
				if err := os.WriteFile(jwksPath, jwks(key.N, key.E, "cluster-test"), 0600); err != nil {
					t.Fatal(err)
				}
				verifier, err := workloadidentity.NewJWKSVerifier("https://cluster.example", "tikti-workload-exchange", "file://"+jwksPath, &http.Client{Timeout: time.Second}, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				verifier.WithClusterRef("cluster-1")
				service := NewWorkloadIdentityService(nil, verifier, "https://issuer", users.jwksPrivateKey, "kid", time.Hour, WithWorkloadAIGateway(users.aiGateway.cfg, authority, &topicTenantReader{tenant: tenant}, users))
				sign := func(sa, pod string) string {
					now := time.Now().Unix()
					claims := jwt.MapClaims{"iss": "https://cluster.example", "sub": "system:serviceaccount:workload-tenant-1:worker", "aud": []string{"tikti-workload-exchange"}, "iat": now, "nbf": now, "exp": now + 90, "kubernetes.io": map[string]any{"namespace": "workload-tenant-1", "serviceaccount": map[string]any{"name": "worker", "uid": sa}, "pod": map[string]any{"name": "worker-pod", "uid": pod}}}
					token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
					token.Header["kid"] = "cluster-test"
					raw, err := token.SignedString(key)
					if err != nil {
						t.Fatal(err)
					}
					return raw
				}
				request := domain.WorkloadTokenExchangeReq{SubjectToken: sign("sa-1", "pod-1"), SubjectTokenType: domain.WorkloadSubjectTokenType, Audience: aigateway.Audience, TenantID: tenant.Id, Scopes: []string{aigateway.InvokeScope}}
				setUser := func() {
					if kind == "Delegated" {
						user, err := users.TokenExchange(t.Context(), userRequest)
						if err != nil {
							t.Fatalf("real User authority callback failed: %v", err)
						}
						request.UserToken = user.AccessToken
					}
				}
				setUser()
				oldReport := interopIdentityReport(t, peer.sync(t), "sa-1", "pod-1")
				peer.sync(t, oldReport)
				issued, err := service.Exchange(t.Context(), request)
				if err != nil {
					t.Fatalf("real current callback failed: %v", err)
				}
				claims, err := users.ValidateAIAccessToken(t.Context(), issued.AccessToken)
				if err != nil || claims.PrincipalKind != kind {
					t.Fatalf("real current token validation failed: %v", err)
				}
				state := peer.control(t, "snapshot", "", "")
				observed := state["status"].(map[string]any)["workloadIdentity"].(map[string]any)
				original := oldReport["workloadIdentity"].(map[string]any)
				if observed["observedAt"] != original["observedAt"] || observed["contextObservedAt"] != original["contextObservedAt"] {
					t.Fatal("real HTTP mirror renewed original clocks")
				}
				switch change {
				case "service":
					peer.control(t, "replace", "service-2", epoch)
					peer.sync(t, oldReport)
				case "tenant":
					tenant.CreatedAt = tenant.CreatedAt.Add(time.Second)
					epoch, err = users.aiGateway.tenant(t.Context(), tenant.Id, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					peer.control(t, "tenant", "", epoch)
					if peer.sync(t, oldReport)["workloadIdentityContext"] != nil {
						t.Fatal("new tenant lifetime adopted old Service")
					}
				case "expired-context":
					original["contextObservedAt"] = time.Now().UTC().Add(-121 * time.Second).Format(time.RFC3339Nano)
					peer.sync(t, oldReport)
				}
				if _, err := verifier.Verify(t.Context(), request.SubjectToken); err != nil {
					t.Fatal("projected token must still be cryptographically valid")
				}
				if got, err := service.Exchange(t.Context(), request); err == nil || got != nil {
					t.Fatal("old unexpired projected identity acquired current authority")
				}
				if _, err := users.ValidateAIAccessToken(t.Context(), issued.AccessToken); err == nil {
					t.Fatal("old issued token retained withdrawn authority")
				}
				if change == "tenant" {
					peer.control(t, "replace", "service-2", epoch)
				}
				peer.sync(t, interopIdentityReport(t, peer.sync(t), "sa-2", "pod-2"))
				request.SubjectToken = sign("sa-2", "pod-2")
				setUser()
				fresh, err := service.Exchange(t.Context(), request)
				if err != nil {
					t.Fatalf("current identity failed after renewal: %v", err)
				}
				freshClaims, err := users.ValidateAIAccessToken(t.Context(), fresh.AccessToken)
				if err != nil {
					t.Fatalf("current token failed real callback validation: %v", err)
				}
				expectedUID := "service-2"
				if change == "expired-context" {
					expectedUID = "service-1"
				}
				if freshClaims.TenantEpoch != epoch || freshClaims.PrincipalKind != kind || (kind == "Workload" && (freshClaims.Workload == nil || freshClaims.Workload.ServiceUID != expectedUID)) || (kind == "Delegated" && (freshClaims.Actor == nil || freshClaims.Actor.ServiceUID != expectedUID)) {
					t.Fatal("new token is not pinned to current Service and tenant lifetime")
				}
			})
		}
	}
}
