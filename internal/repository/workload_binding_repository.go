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

type WorkloadBindingRepository interface {
	Upsert(ctx context.Context, binding *domain.WorkloadBinding) error
	Get(ctx context.Context, subject string) (*domain.WorkloadBinding, error)
	Revoke(ctx context.Context, subject string, revokedAt time.Time) (*domain.WorkloadBinding, error)
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
	return r.client.HSet(ctx, workloadBindingsKey, binding.Subject, raw).Err()
}

func (r *workloadBindingRepo) Get(ctx context.Context, subject string) (*domain.WorkloadBinding, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, domain.ErrInvalidArgument
	}
	raw, err := r.client.HGet(ctx, workloadBindingsKey, subject).Result()
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
	return &binding, nil
}

func (r *workloadBindingRepo) Revoke(ctx context.Context, subject string, revokedAt time.Time) (*domain.WorkloadBinding, error) {
	binding, err := r.Get(ctx, subject)
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
