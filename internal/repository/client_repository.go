package repository

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type ClientRepository interface {
	Create(ctx context.Context, tenantID string, client *domain.Client) error
	Get(ctx context.Context, tenantID string, clientID string) (*domain.Client, error)
	List(ctx context.Context, tenantID string) ([]*domain.Client, error)
}

type clientRepo struct {
	client *redis.Client
}

func NewClientRepo(rdb *redis.Client) ClientRepository {
	return &clientRepo{client: rdb}
}

func (r *clientRepo) Create(ctx context.Context, tenantID string, client *domain.Client) error {
	tenantID = strings.TrimSpace(tenantID)
	if client == nil {
		return domain.ErrInvalidArgument
	}
	clientID := strings.TrimSpace(client.Id)
	if tenantID == "" || clientID == "" {
		return domain.ErrInvalidArgument
	}
	client.Id = clientID
	data, err := json.Marshal(client)
	if err != nil {
		return err
	}
	return r.client.HSet(ctx, clientsKey(tenantID), clientID, data).Err()
}

func (r *clientRepo) Get(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
	val, err := r.client.HGet(ctx, clientsKey(tenantID), clientID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if val == "" {
		return nil, nil
	}
	var client domain.Client
	if e := json.Unmarshal([]byte(val), &client); e != nil {
		return nil, e
	}
	return &client, nil
}

func (r *clientRepo) List(ctx context.Context, tenantID string) ([]*domain.Client, error) {
	vals, err := r.client.HGetAll(ctx, clientsKey(tenantID)).Result()
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Client, 0, len(vals))
	for _, v := range vals {
		var c domain.Client
		if e := json.Unmarshal([]byte(v), &c); e != nil {
			return nil, e
		}
		out = append(out, &c)
	}
	return out, nil
}

func clientsKey(tenantID string) string {
	return "clients:" + tenantID
}
