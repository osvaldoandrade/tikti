package services

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/osvaldoandrade/tikti/internal/codeqbinding"
	"github.com/osvaldoandrade/tikti/internal/managedlogs"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type ManagedLogsExchangeConfig struct {
	Enabled              bool
	TTL                  time.Duration
	MaximumConcurrent    int
	PerIdentityPerMinute int
}
type managedLogsExchange struct {
	cfg       ManagedLogsExchangeConfig
	authority managedlogs.Authority
	tenants   CodeQTopicTenantReader
	slots     chan struct{}
	limiter   *codeqbinding.IdentityRateLimiter
}

func WithManagedLogs(cfg ManagedLogsExchangeConfig, authority managedlogs.Authority, tenants CodeQTopicTenantReader) WorkloadIdentityServiceOption {
	return func(s *workloadIdentityService) {
		e := &managedLogsExchange{cfg: cfg, authority: authority, tenants: tenants}
		if cfg.MaximumConcurrent > 0 && cfg.MaximumConcurrent <= 32 {
			e.slots = make(chan struct{}, cfg.MaximumConcurrent)
		}
		if cfg.PerIdentityPerMinute > 0 && cfg.PerIdentityPerMinute <= 60 {
			e.limiter = codeqbinding.NewIdentityRateLimiter(cfg.PerIdentityPerMinute, time.Minute)
		}
		s.managedLogs = e
	}
}

func logsExchangeShape(r domain.WorkloadTokenExchangeReq) ([]string, bool) {
	if r.SubjectTokenType != domain.WorkloadSubjectTokenType || strings.TrimSpace(r.SubjectToken) == "" || r.CodeQTopicID != "" || !managedlogs.ValidGrantKind(r.LogsGrant, r.LogsGrantKind) {
		return nil, false
	}
	var scopes []string
	switch r.LogsGrant {
	case "Ingest":
		if r.Audience != "logs-ingest" {
			return nil, false
		}
		scopes = []string{"logs:ingest"}
	case "Resolve":
		if r.Audience != managedlogs.AuthorityAudience {
			return nil, false
		}
		scopes = []string{}
	case "CefasBootstrap", "CefasRuntime":
		if r.Audience != managedlogs.StoreAudience {
			return nil, false
		}
		scopes = managedlogs.StoreScopes(r.LogsGrant)
	case "Publish":
		if r.Audience != domain.WorkloadProducerAudience {
			return nil, false
		}
		scopes = codeqPublishScopes
	case "Subscribe":
		if r.Audience != domain.WorkloadWorkerAudience {
			return nil, false
		}
		scopes = codeqSubscribeScopes
	default:
		return nil, false
	}
	requested := slices.Clone(r.Scopes)
	slices.Sort(requested)
	if len(r.Scopes) != len(scopes) || !slices.Equal(requested, scopes) {
		return nil, false
	}
	if r.LogsGrant == "Ingest" || r.LogsGrant == "Resolve" || r.LogsGrant == "CefasBootstrap" || r.LogsGrant == "CefasRuntime" {
		return scopes, r.TenantID == "" && r.LogsConfigUID == "" && r.LogsConfigGeneration == 0
	}
	return scopes, tenantIDPattern.MatchString(r.TenantID) && r.LogsConfigUID != "" && len(r.LogsConfigUID) <= 128 && r.LogsConfigGeneration > 0
}

func (s *workloadIdentityService) exchangeManagedLogs(ctx context.Context, r domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
	refuse := func(status int, code string) (*domain.WorkloadTokenExchangeResp, error) {
		return nil, &domain.WorkloadExchangeError{Status: status, Code: code, CorrelationID: uuid.NewString()}
	}
	e := s.managedLogs
	if e == nil || !e.cfg.Enabled {
		return refuse(http.StatusForbidden, "LogsFeatureDisabled")
	}
	scopes, ok := logsExchangeShape(r)
	if !ok {
		return refuse(http.StatusBadRequest, "LogsInvalidRequest")
	}
	if e.authority == nil || e.slots == nil || e.limiter == nil || e.cfg.TTL < 30*time.Second || e.cfg.TTL > 300*time.Second {
		return refuse(http.StatusServiceUnavailable, "LogsAuthorityUnavailable")
	}
	subject, err := s.VerifyProjectedToken(ctx, r.SubjectToken)
	if err != nil {
		if errors.Is(err, domain.ErrWorkloadTokenInvalid) {
			return refuse(401, "SubjectTokenInvalid")
		}
		return refuse(503, "IdentityUnavailable")
	}
	canonical, valid := domain.ParseWorkloadSubject(subject.Subject)
	if !valid || canonical.Subject != subject.Subject || canonical.Namespace != subject.Namespace || canonical.ServiceAccount != subject.ServiceAccount || !domain.ValidWorkloadClusterRef(subject.ClusterRef) || !codeqbinding.ValidCanonicalUUID(subject.ServiceAccountUID) || !codeqbinding.ValidCanonicalUUID(subject.PodUID) || subject.ExpiresAt.IsZero() {
		return refuse(401, "UnboundSubjectToken")
	}
	if r.LogsGrant == "Publish" || r.LogsGrant == "Subscribe" {
		if e.tenants == nil {
			return refuse(503, "IdentityUnavailable")
		}
		tenant, err := e.tenants.GetRetained(ctx, r.TenantID, s.now().UTC())
		if err != nil {
			return refuse(503, "IdentityUnavailable")
		}
		if !activeTenant(tenant, r.TenantID, s.now().UTC()) {
			return refuse(403, "TenantInactive")
		}
	}
	if allowed, retry := e.limiter.Allow(codeqbinding.IdentityKey(subject.ClusterRef, subject.Namespace, subject.ServiceAccount, subject.PodUID)); !allowed {
		return nil, &domain.WorkloadExchangeError{Status: 429, Code: "LogsRateLimited", CorrelationID: uuid.NewString(), RetryAfterSeconds: retry}
	}
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		return refuse(503, "LogsAuthorityBusy")
	}
	request := managedlogs.Request{SchemaVersion: managedlogs.Version, RequestID: uuid.NewString(), Operation: r.LogsGrant, GrantKind: r.LogsGrantKind, Identity: managedlogs.Identity{ClusterRef: subject.ClusterRef, Namespace: subject.Namespace, ServiceAccountName: subject.ServiceAccount, ServiceAccountUID: subject.ServiceAccountUID, PodUID: subject.PodUID}, TenantID: r.TenantID, ConfigUID: r.LogsConfigUID, ConfigGeneration: r.LogsConfigGeneration}
	assertion, err := s.signLogsAssertion(managedlogs.AuthoritySubject)
	if err != nil {
		return refuse(503, "IdentityUnavailable")
	}
	decision, err := e.authority.Authorize(ctx, request, assertion)
	if err != nil || !managedlogs.ValidDecision(request, decision) {
		return refuse(503, "LogsAuthorityUnavailable")
	}
	if !decision.Allowed {
		return refuse(403, "LogsGrantDenied")
	}
	return s.issueLogsToken(subject, r, scopes, decision)
}

func (s *workloadIdentityService) signLogsAssertion(subject string) (string, error) {
	key, err := s.signingKey()
	if err != nil || s.issuer == "" || s.keyID == "" {
		return "", domain.ErrWorkloadIdentityUnavailable
	}
	now := s.now().UTC().Truncate(time.Second)
	claims := jwt.MapClaims{"iss": strings.TrimSuffix(s.issuer, "/"), "aud": managedlogs.AuthorityAudience, "sub": subject, "jti": uuid.NewString(), "iat": now.Unix(), "nbf": now.Add(-5 * time.Second).Unix(), "exp": now.Add(60 * time.Second).Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID
	return token.SignedString(key)
}

func (s *workloadIdentityService) issueLogsToken(subject domain.WorkloadSubject, r domain.WorkloadTokenExchangeReq, scopes []string, d managedlogs.Decision) (*domain.WorkloadTokenExchangeResp, error) {
	now := s.now().UTC().Truncate(time.Second)
	ttl := min(s.managedLogs.cfg.TTL, subject.ExpiresAt.Sub(now).Truncate(time.Second))
	if r.LogsGrant == "Resolve" {
		ttl = min(ttl, time.Minute)
	}
	if ttl < 30*time.Second {
		return nil, &domain.WorkloadExchangeError{Status: 401, Code: "SubjectTokenExpiring", CorrelationID: uuid.NewString()}
	}
	if r.LogsGrant == "Publish" || r.LogsGrant == "Subscribe" {
		binding := codeqbinding.Binding{BindingUID: d.GrantUID, Generation: d.GrantGeneration, TopicID: d.TopicID, TopicName: managedlogs.TopicName, Policy: r.LogsGrant}
		raw, _, _, err := s.signCodeQBindingToken(subject, r.TenantID, r.Audience, scopes, managedlogs.TopicName, binding, now, ttl)
		if err != nil {
			return nil, domain.ErrWorkloadIdentityUnavailable
		}
		return &domain.WorkloadTokenExchangeResp{AccessToken: raw, TokenType: "Bearer", ExpiresIn: int(ttl / time.Second), Audience: r.Audience, Scopes: slices.Clone(scopes), TenantID: r.TenantID, EventTypes: []string{managedlogs.TopicName}}, nil
	}
	key, err := s.signingKey()
	if err != nil || s.issuer == "" || s.keyID == "" {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	claims := jwt.MapClaims{"iss": strings.TrimSuffix(s.issuer, "/"), "aud": r.Audience, "sub": CodeQBindingSubject(subject.ClusterRef, subject.Namespace, subject.ServiceAccount, subject.PodUID), "iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": uuid.NewString()}
	if r.LogsGrant == "Resolve" {
		claims["sub"] = managedlogs.GatewaySubject
		claims["nbf"] = now.Add(-5 * time.Second).Unix()
	} else if r.LogsGrant == "Ingest" {
		claims["scope"] = "logs:ingest"
		claims["logs_collector"] = map[string]any{"schemaVersion": managedlogs.CollectorVersion, "installationId": d.InstallationID, "clusterUID": d.ClusterUID, "clusterRef": subject.ClusterRef, "namespace": subject.Namespace, "serviceAccountName": subject.ServiceAccount, "serviceAccountUid": subject.ServiceAccountUID, "podUid": subject.PodUID, "grantUID": d.GrantUID, "grantGeneration": d.GrantGeneration}
	} else if r.LogsGrant == "CefasBootstrap" || r.LogsGrant == "CefasRuntime" {
		scopes = managedlogs.StoreScopes(r.LogsGrant)
		claims["aud"] = managedlogs.StoreAudience
		claims["scope"] = strings.Join(scopes, " ")
	} else {
		return nil, domain.ErrInvalidArgument
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID
	raw, err := token.SignedString(key)
	if err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	return &domain.WorkloadTokenExchangeResp{AccessToken: raw, TokenType: "Bearer", ExpiresIn: int(ttl / time.Second), Audience: r.Audience, Scopes: scopes, TenantID: ""}, nil
}
