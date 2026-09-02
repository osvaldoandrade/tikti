package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

var errManagedAudienceClientContract = errors.New("managed audience client contract mismatch")

type ClientService interface {
	Create(ctx context.Context, tenantID string, req domain.ClientCreateReq) (*domain.ClientResp, error)
	EnsureCodeAdminAudience(ctx context.Context, tenantID string, req domain.ManagedAudienceClientEnsureReq) (*domain.ManagedAudienceClientResp, bool, error)
	Get(ctx context.Context, tenantID string, clientID string) (*domain.ClientResp, error)
	List(ctx context.Context, tenantID string) ([]*domain.ClientResp, error)
	GetClient(ctx context.Context, tenantID string, clientID string) (*domain.Client, error)
}

type clientService struct {
	repo                          repository.ClientRepository
	managedAudienceEnabled        bool
	managedAudienceTenants        map[string]struct{}
	dynamicManagedAudienceEnabled bool
	dynamicManagedAudienceTenants repository.TenantRepository
}

type ClientServiceOption func(*clientService)

func NewClientService(repo repository.ClientRepository, options ...ClientServiceOption) ClientService {
	service := &clientService{repo: repo}
	for _, option := range options {
		if option != nil {
			option(service)
		}
	}
	return service
}

// WithManagedAudienceClients restricts managed clients to the strict tenant canary.
func WithManagedAudienceClients(enabled bool, tenants []string) ClientServiceOption {
	return func(service *clientService) {
		service.managedAudienceEnabled = enabled
		service.managedAudienceTenants = make(map[string]struct{}, len(tenants))
		for _, tenantID := range tenants {
			service.managedAudienceTenants[tenantID] = struct{}{}
		}
	}
}

// WithDynamicManagedAudienceClients permits managed-client reconciliation for
// exact active tenants while the controller enforces the principal canary.
func WithDynamicManagedAudienceClients(enabled bool, tenants repository.TenantRepository) ClientServiceOption {
	return func(service *clientService) {
		service.dynamicManagedAudienceEnabled = enabled
		service.dynamicManagedAudienceTenants = tenants
	}
}

func (s *clientService) Create(ctx context.Context, tenantID string, req domain.ClientCreateReq) (*domain.ClientResp, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, domain.ErrInvalidTenant
	}
	if strings.TrimSpace(req.ClientId) == "" {
		return nil, domain.ErrInvalidArgument
	}
	clientType := domain.ClientTypeService
	if req.Type != "" {
		clientType = domain.ClientType(strings.ToUpper(req.Type))
	}
	secret := generateSecret(32)
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	client := &domain.Client{
		Id:                req.ClientId,
		TenantId:          tenantID,
		SecretHash:        string(hash),
		Type:              clientType,
		AllowedGrantTypes: normalizeList(req.AllowedGrantTypes),
		DefaultScopes:     normalizeList(req.DefaultScopes),
		Status:            "ACTIVE",
	}
	if err := s.repo.Create(ctx, tenantID, client); err != nil {
		return nil, err
	}
	return &domain.ClientResp{
		ClientId:          client.Id,
		Type:              string(client.Type),
		AllowedGrantTypes: client.AllowedGrantTypes,
		DefaultScopes:     client.DefaultScopes,
		Secret:            secret,
	}, nil
}

// EnsureCodeAdminAudience creates or replays the reserved credential-free client.
func (s *clientService) EnsureCodeAdminAudience(
	ctx context.Context,
	tenantID string,
	req domain.ManagedAudienceClientEnsureReq,
) (*domain.ManagedAudienceClientResp, bool, error) {
	if (!s.managedAudienceEnabled && !s.dynamicManagedAudienceEnabled) || !validRoleTenantID(tenantID) {
		return nil, false, domain.ErrInvalidTenant
	}
	if _, allowed := s.managedAudienceTenants[tenantID]; !allowed {
		if !s.dynamicManagedAudienceEnabled || s.dynamicManagedAudienceTenants == nil {
			return nil, false, domain.ErrInvalidTenant
		}
		tenant, err := s.dynamicManagedAudienceTenants.Get(ctx, tenantID)
		if err != nil {
			return nil, false, err
		}
		if tenant == nil || tenant.Id != tenantID || tenant.Status != domain.TenantStatusActive {
			return nil, false, domain.ErrInvalidTenant
		}
	}
	defaultScopes, ok := scopepolicy.CanonicalAudienceScopes(req.DefaultScopes)
	if !ok {
		return nil, false, domain.ErrInvalidArgument
	}
	desired := &domain.Client{
		Id:                domain.CodeAdminAudienceClientID,
		TenantId:          tenantID,
		Type:              domain.ClientTypeService,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     defaultScopes,
		Status:            domain.ClientStatusActive,
		ManagedBy:         domain.CodeAdminAudienceClientManager,
	}
	stored, created, err := s.repo.EnsureManagedAudience(ctx, tenantID, desired)
	if err != nil {
		return nil, false, err
	}
	if !sameManagedAudienceDefinition(stored, desired) {
		return nil, false, errManagedAudienceClientContract
	}
	return &domain.ManagedAudienceClientResp{
		ClientId: stored.Id, TenantId: stored.TenantId, Type: stored.Type,
		AllowedGrantTypes: append([]string(nil), stored.AllowedGrantTypes...),
		DefaultScopes:     append([]string(nil), stored.DefaultScopes...),
		Status:            stored.Status,
	}, created, nil
}

func sameManagedAudienceDefinition(left, right *domain.Client) bool {
	return left != nil && right != nil && domain.IsManagedCodeAdminAudience(left.TenantId, left) &&
		domain.IsManagedCodeAdminAudience(right.TenantId, right) && left.TenantId == right.TenantId &&
		slices.Equal(left.DefaultScopes, right.DefaultScopes)
}

func (s *clientService) Get(ctx context.Context, tenantID string, clientID string) (*domain.ClientResp, error) {
	client, err := s.repo.Get(ctx, tenantID, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, domain.ErrNotFound
	}
	return &domain.ClientResp{
		ClientId:          client.Id,
		Type:              string(client.Type),
		AllowedGrantTypes: client.AllowedGrantTypes,
		DefaultScopes:     client.DefaultScopes,
	}, nil
}

func (s *clientService) List(ctx context.Context, tenantID string) ([]*domain.ClientResp, error) {
	clients, err := s.repo.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.ClientResp, 0, len(clients))
	for _, c := range clients {
		out = append(out, &domain.ClientResp{
			ClientId:          c.Id,
			Type:              string(c.Type),
			AllowedGrantTypes: c.AllowedGrantTypes,
			DefaultScopes:     c.DefaultScopes,
		})
	}
	return out, nil
}

func (s *clientService) GetClient(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
	return s.repo.Get(ctx, tenantID, clientID)
}

func generateSecret(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}
