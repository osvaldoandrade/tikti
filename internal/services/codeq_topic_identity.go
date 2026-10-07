package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const CodeQTopicManageScope = "codeq:topics:manage"

// CodeQTopicControllerIdentity is installation-owned authority, never request input.
// An issuer provider verifies the projected token before this exact lifetime fence.
type CodeQTopicControllerIdentity struct {
	Enabled           bool   `yaml:"enabled"`
	Issuer            string `yaml:"issuer"`
	ClusterRef        string `yaml:"clusterRef"`
	Namespace         string `yaml:"namespace"`
	ServiceAccount    string `yaml:"serviceAccount"`
	ServiceAccountUID string `yaml:"serviceAccountUID"`
}
type CodeQTopicTenantReader interface {
	GetRetained(context.Context, string, time.Time) (*domain.Tenant, error)
}
type CodeQTopicAuthority struct {
	SchemaVersion string `json:"schemaVersion"`
	TenantID      string `json:"tenantId"`
	TenantEpoch   string `json:"tenantEpoch"`
	Active        bool   `json:"active"`
}

func WithCodeQTopicController(policy CodeQTopicControllerIdentity, reader CodeQTopicTenantReader) WorkloadIdentityServiceOption {
	return func(s *workloadIdentityService) { s.topicController = policy; s.topicTenants = reader }
}
func (p CodeQTopicControllerIdentity) valid() bool {
	subject, valid := domain.ParseWorkloadSubject("system:serviceaccount:" + p.Namespace + ":" + p.ServiceAccount)
	return p.Enabled && valid && subject.Namespace == p.Namespace && p.Issuer != "" && p.ClusterRef != "" && p.ServiceAccountUID != ""
}
func (p CodeQTopicControllerIdentity) digest() string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (s *workloadIdentityService) topicAuthority(ctx context.Context, tenantID string) (CodeQTopicAuthority, error) {
	empty := CodeQTopicAuthority{}
	if !s.topicController.valid() || s.topicTenants == nil || !tenantIDPattern.MatchString(tenantID) {
		return empty, domain.ErrWorkloadBindingDenied
	}
	now := s.now().UTC()
	tenant, err := s.topicTenants.GetRetained(ctx, tenantID, now)
	if err != nil {
		return empty, domain.ErrWorkloadIdentityUnavailable
	}
	if !activeTenant(tenant, tenantID, now) {
		return empty, domain.ErrWorkloadBindingDenied
	}
	sum := sha256.Sum256([]byte("codefoundry/tenant-lifetime/v1\x00" + tenantID + "\x00" + tenant.CreatedAt.UTC().Format(time.RFC3339Nano)))
	return CodeQTopicAuthority{SchemaVersion: "codeq-topic-authority/v1", TenantID: tenantID, TenantEpoch: hex.EncodeToString(sum[:]), Active: true}, nil
}

// activeTenant is the single tenant-lifetime predicate shared by the topic
// controller authority and the ADR-0022 binding exchange.
func activeTenant(tenant *domain.Tenant, tenantID string, now time.Time) bool {
	return tenant != nil && tenant.Id == tenantID && tenant.Status == domain.TenantStatusActive && tenant.RetiredAt == nil && !tenant.CreatedAt.IsZero() && !tenant.CreatedAt.After(now)
}

func (s *workloadIdentityService) exchangeCodeQTopic(ctx context.Context, req domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
	if len(req.Scopes) != 1 || req.Scopes[0] != CodeQTopicManageScope || req.Audience != domain.WorkloadProducerAudience || !s.topicController.valid() {
		return nil, domain.ErrWorkloadBindingDenied
	}
	subject, err := s.VerifyProjectedToken(ctx, req.SubjectToken)
	if err != nil {
		return nil, err
	}
	p := s.topicController
	if subject.Issuer != p.Issuer || subject.ClusterRef != p.ClusterRef || subject.Namespace != p.Namespace || subject.ServiceAccount != p.ServiceAccount || subject.ServiceAccountUID != p.ServiceAccountUID || subject.PodUID == "" || subject.Subject != "system:serviceaccount:"+p.Namespace+":"+p.ServiceAccount {
		return nil, domain.ErrWorkloadBindingDenied
	}
	authority, err := s.topicAuthority(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if s.issuer == "" || s.keyID == "" {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	key, err := s.signingKey()
	if err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	now := s.now().UTC()
	ttl := time.Minute
	if s.ttl < ttl {
		ttl = s.ttl
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": s.issuer, "aud": domain.WorkloadProducerAudience, "sub": subject.Subject, "tid": authority.TenantID, "tenant_epoch": authority.TenantEpoch, "scope": CodeQTopicManageScope, "topic_controller": p.digest(), "iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": uuid.NewString()})
	token.Header["kid"] = s.keyID
	raw, err := token.SignedString(key)
	if err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	return &domain.WorkloadTokenExchangeResp{AccessToken: raw, TokenType: "Bearer", ExpiresIn: int(ttl / time.Second), Audience: domain.WorkloadProducerAudience, Scopes: []string{CodeQTopicManageScope}, TenantID: authority.TenantID}, nil
}

// ValidateCodeQTopicToken checks current authority at use time: short expiry alone
// cannot fence a retired/recreated tenant or a replaced controller installation.
func (s *workloadIdentityService) ValidateCodeQTopicToken(ctx context.Context, raw string) (CodeQTopicAuthority, error) {
	empty := CodeQTopicAuthority{}
	if len(raw) > 16384 || !s.topicController.valid() {
		return empty, domain.ErrWorkloadBindingDenied
	}
	key, err := s.signingKey()
	if err != nil {
		return empty, domain.ErrWorkloadIdentityUnavailable
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Header["kid"] != s.keyID {
			return nil, domain.ErrWorkloadTokenInvalid
		}
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.issuer), jwt.WithAudience(domain.WorkloadProducerAudience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(s.now))
	if err != nil || !token.Valid || claims["scope"] != CodeQTopicManageScope || claims["topic_controller"] != s.topicController.digest() || claims["sub"] != "system:serviceaccount:"+s.topicController.Namespace+":"+s.topicController.ServiceAccount {
		return empty, domain.ErrWorkloadBindingDenied
	}
	tid, ok := claims["tid"].(string)
	if !ok {
		return empty, domain.ErrWorkloadBindingDenied
	}
	authority, err := s.topicAuthority(ctx, tid)
	if err != nil {
		return empty, err
	}
	if claims["tenant_epoch"] != authority.TenantEpoch {
		return empty, domain.ErrWorkloadBindingDenied
	}
	return authority, nil
}
