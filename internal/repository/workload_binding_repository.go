package repository

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const workloadBindingsKey = "workloadBindings"

// WorkloadBindingRepository stores WorkloadBinding records under
// domain.WorkloadBindingKey(binding.ClusterRef, binding.Subject). Get and
// Revoke take that storage key: the bare subject for unscoped legacy records,
// or clusterRef + NUL + subject for scoped records.
type WorkloadBindingRepository interface {
	Upsert(ctx context.Context, binding *domain.WorkloadBinding) error
	Get(ctx context.Context, key string) (*domain.WorkloadBinding, error)
	Revoke(ctx context.Context, key string, revokedAt time.Time) (*domain.WorkloadBinding, error)
}

type workloadBindingRepo struct {
	client *redis.Client
}

func NewWorkloadBindingRepo(client *redis.Client) WorkloadBindingRepository {
	return &workloadBindingRepo{client: client}
}

func (r *workloadBindingRepo) Upsert(ctx context.Context, binding *domain.WorkloadBinding) error {
	if binding == nil || strings.TrimSpace(binding.Subject) == "" {
		return domain.ErrInvalidArgument
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	return r.client.HSet(ctx, workloadBindingsKey, domain.WorkloadBindingKey(binding.ClusterRef, binding.Subject), raw).Err()
}

func (r *workloadBindingRepo) Get(ctx context.Context, key string) (*domain.WorkloadBinding, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, domain.ErrInvalidArgument
	}
	raw, err := r.client.HGet(ctx, workloadBindingsKey, key).Result()
	if err == redis.Nil || raw == "" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var binding domain.WorkloadBinding
	if err := json.Unmarshal([]byte(raw), &binding); err != nil {
		return nil, err
	}
	if domain.WorkloadBindingKey(binding.ClusterRef, binding.Subject) != key {
		// A record whose content disagrees with its key is never authority.
		return nil, domain.ErrInvalidArgument
	}
	return &binding, nil
}

func (r *workloadBindingRepo) Revoke(ctx context.Context, key string, revokedAt time.Time) (*domain.WorkloadBinding, error) {
	binding, err := r.Get(ctx, key)
	if err != nil || binding == nil {
		return binding, err
	}
	binding.Revoked = true
	binding.UpdatedAt = revokedAt.UTC()
	if err := r.Upsert(ctx, binding); err != nil {
		return nil, err
	}
	return binding, nil
}
