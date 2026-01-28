package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type ClientService interface {
	Create(ctx context.Context, tenantID string, req domain.ClientCreateReq) (*domain.ClientResp, error)
	Get(ctx context.Context, tenantID string, clientID string) (*domain.ClientResp, error)
	List(ctx context.Context, tenantID string) ([]*domain.ClientResp, error)
	GetClient(ctx context.Context, tenantID string, clientID string) (*domain.Client, error)
}

type clientService struct {
	repo repository.ClientRepository
}

func NewClientService(repo repository.ClientRepository) ClientService {
	return &clientService{repo: repo}
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
