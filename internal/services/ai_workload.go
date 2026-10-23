package services

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/internal/codeqbinding"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func aiSubjectValid(s domain.WorkloadSubject, now time.Time) bool {
	p, ok := domain.ParseWorkloadSubject(s.Subject)
	return ok && p.Namespace == s.Namespace && p.ServiceAccount == s.ServiceAccount && s.Issuer != "" && domain.ValidWorkloadClusterRef(s.ClusterRef) && domain.ValidWorkloadObjectUID(s.ServiceAccountUID) && domain.ValidWorkloadObjectUID(s.PodUID) && s.ExpiresAt.After(now)
}

func (s *workloadIdentityService) exchangeAIWorkload(ctx context.Context, r domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
	e := s.aiGateway
	if !e.ready() {
		return nil, domain.ErrWorkloadBindingDenied
	}
	if r.SubjectTokenType != domain.WorkloadSubjectTokenType || r.SubjectToken == "" || len(r.SubjectToken) > 16384 || r.CodeQTopicID != "" || r.LogsGrant != "" || r.LogsGrantKind != "" || r.LogsConfigUID != "" || r.LogsConfigGeneration != 0 {
		return nil, domain.ErrInvalidArgument
	}
	subject, err := s.VerifyProjectedToken(ctx, r.SubjectToken)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Second)
	if !aiSubjectValid(subject, now) {
		return nil, domain.ErrWorkloadTokenInvalid
	}
	if allowed, _ := e.limiter.Allow(codeqbinding.IdentityKey(subject.ClusterRef, subject.Namespace, subject.ServiceAccount, subject.PodUID)); !allowed {
		return nil, domain.ErrRateLimited
	}
	if r.AIGrant != "" {
		return s.exchangeAIMachine(ctx, r, subject, now)
	}
	scopes, valid := aigateway.Scopes(r.Scopes)
	if !valid || r.Audience != aigateway.Audience || r.UserToken == "" && slices.Contains(scopes, aigateway.UsageScope) {
		return nil, domain.ErrWorkloadBindingDenied
	}
	identity := aigateway.Identity{SchemaVersion: aigateway.IdentityVersion, Kind: "Workload", Subject: subject.Subject, TenantID: r.TenantID, Scopes: scopes, Workload: &aigateway.WorkloadRequest{Issuer: subject.Issuer, ClusterRef: subject.ClusterRef, Namespace: subject.Namespace, ServiceAccount: subject.ServiceAccount, ServiceAccountUID: subject.ServiceAccountUID, PodUID: subject.PodUID}}
	ttl := min(time.Duration(e.cfg.AccessTokenTTLSeconds)*time.Second, subject.ExpiresAt.Sub(now).Truncate(time.Second))
	var user aigateway.Claims
	if r.UserToken != "" {
		if e.users == nil {
			return nil, domain.ErrWorkloadBindingDenied
		}
		user, err = e.users.ValidateAIAccessToken(ctx, r.UserToken)
		if err != nil || user.PrincipalKind != "User" || user.Actor != nil || user.Workload != nil || user.Version == nil || user.TenantID != r.TenantID || !subset(scopes, strings.Split(user.Scope, " ")) {
			return nil, domain.ErrWorkloadBindingDenied
		}
		identity.Kind = "Delegated"
		identity.Subject = user.Subject
		ttl = min(ttl, time.Unix(user.ExpiresAt, 0).Sub(now))
	}
	if ttl < time.Second {
		return nil, domain.ErrWorkloadTokenInvalid
	}
	key, err := s.signingKey()
	if err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	p, err := e.authorize(ctx, identity, key, s.issuer, s.keyID, now)
	if err != nil {
		return nil, err
	}
	if r.UserToken != "" && (p.TenantUID != user.TenantUID || p.TenantEpoch != user.TenantEpoch) {
		return nil, domain.ErrWorkloadBindingDenied
	}
	claims := aiPrincipalClaims(p, s.issuer, scopes, now, ttl)
	if identity.Kind == "Workload" {
		claims["workload"] = p.Workload
	} else {
		w := p.Workload
		claims["ver"] = *user.Version
		claims["act"] = aigateway.Actor{Subject: "codefoundry:service:" + w.ServiceUID, Issuer: w.Issuer, ServiceUID: w.ServiceUID, ClusterRef: w.ClusterRef, Namespace: w.Namespace, ServiceAccount: w.ServiceAccount, ServiceAccountUID: w.ServiceAccountUID, PodUID: w.PodUID}
	}
	raw, err := signAIClaims(key, s.keyID, claims)
	if err != nil {
		return nil, err
	}
	return &domain.WorkloadTokenExchangeResp{AccessToken: raw, TokenType: "Bearer", ExpiresIn: int(ttl / time.Second), Audience: r.Audience, Scopes: scopes, TenantID: r.TenantID}, nil
}

func aiMachineMatches(p config.AIMachineIdentity, s domain.WorkloadSubject) bool {
	return p.Enabled && p.Issuer != "" && p.ClusterRef != "" && p.ServiceAccountUID != "" && s.Issuer == p.Issuer && s.ClusterRef == p.ClusterRef && s.Namespace == p.Namespace && s.ServiceAccount == p.ServiceAccount && s.ServiceAccountUID == p.ServiceAccountUID
}

// AI store grants are isolated from Logs and contain no table-delete, item-delete,
// describe/CDC or unbounded query authority. Bootstrap uses a separately pinned
// identity on the dedicated store, whose existing API has global create/describe.
func aiStoreScopes(grant string) []string {
	switch grant {
	case "CefasRuntime":
		return []string{"cefas:item:read:ai-usage", "cefas:item:write:ai-usage", "cefas:query:ai-usage"}
	case "CefasBootstrap":
		return []string{"cefas:table:create", "cefas:table:describe"}
	default:
		return nil
	}
}

func (s *workloadIdentityService) exchangeAIMachine(ctx context.Context, r domain.WorkloadTokenExchangeReq, subject domain.WorkloadSubject, now time.Time) (*domain.WorkloadTokenExchangeResp, error) {
	e := s.aiGateway
	p := e.cfg
	if r.UserToken != "" || r.TenantID != p.RuntimeTenantID || !domain.ValidWorkloadObjectUID(p.InstallationUID) {
		return nil, domain.ErrWorkloadBindingDenied
	}
	var scopes []string
	identity := p.Runtime
	ttl := min(time.Minute, subject.ExpiresAt.Sub(now).Truncate(time.Second))
	switch r.AIGrant {
	case "Runtime":
		if r.Audience != aigateway.RuntimeAudience {
			return nil, domain.ErrWorkloadBindingDenied
		}
		scopes = []string{aigateway.RuntimeScope}
	case "CefasRuntime", "CefasBootstrap":
		if p.StoreAudience == "" || p.StoreAudience == "code-admin-logs-store" || p.StoreAudience == aigateway.RuntimeAudience || p.StoreAudience == aigateway.Audience || r.Audience != p.StoreAudience {
			return nil, domain.ErrWorkloadBindingDenied
		}
		identity = p.StoreRuntime
		if r.AIGrant == "CefasBootstrap" {
			identity = p.StoreBootstrap
		}
		scopes = aiStoreScopes(r.AIGrant)
		ttl = min(time.Duration(p.AccessTokenTTLSeconds)*time.Second, subject.ExpiresAt.Sub(now).Truncate(time.Second))
	default:
		return nil, domain.ErrWorkloadBindingDenied
	}
	requested := slices.Clone(r.Scopes)
	slices.Sort(requested)
	if !slices.Equal(requested, scopes) || !aiMachineMatches(identity, subject) || ttl < time.Second {
		return nil, domain.ErrWorkloadBindingDenied
	}
	epoch, err := e.tenant(ctx, r.TenantID, now)
	if err != nil {
		return nil, err
	}
	key, err := s.signingKey()
	if err != nil {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	claims := jwt.MapClaims{"iss": s.issuer, "aud": r.Audience, "sub": "codefoundry:ai-gateway:" + p.InstallationUID, "tid": r.TenantID, "tenant_uid": r.TenantID, "tenant_epoch": epoch, "scope": strings.Join(scopes, " "), "iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": uuid.NewString(), "ai_runtime": aigateway.Runtime{SchemaVersion: aigateway.RuntimeVersion, InstallationUID: p.InstallationUID, ClusterRef: subject.ClusterRef, Namespace: subject.Namespace, ServiceAccount: subject.ServiceAccount, ServiceAccountUID: subject.ServiceAccountUID, PodUID: subject.PodUID}}
	raw, err := signAIClaims(key, s.keyID, claims)
	if err != nil {
		return nil, err
	}
	return &domain.WorkloadTokenExchangeResp{AccessToken: raw, TokenType: "Bearer", ExpiresIn: int(ttl / time.Second), Audience: r.Audience, Scopes: scopes, TenantID: r.TenantID}, nil
}
