package repository

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type RoleRepository interface {
	// Four methods keep legacy overwrite and immutable create behind one storage boundary.
	Create(ctx context.Context, tenantID string, role *domain.Role) error
	CreateIfAbsent(ctx context.Context, tenantID string, role *domain.Role) (*domain.Role, bool, error)
	Get(ctx context.Context, tenantID string, name string) (*domain.Role, error)
	List(ctx context.Context, tenantID string) ([]*domain.Role, error)
}

type roleRepo struct {
	client *redis.Client
}

func NewRoleRepo(rdb *redis.Client) RoleRepository {
	return &roleRepo{client: rdb}
}

func (r *roleRepo) Create(ctx context.Context, tenantID string, role *domain.Role) error {
	tenantID = strings.TrimSpace(tenantID)
	if role == nil {
		return domain.ErrInvalidArgument
	}
	roleName := strings.TrimSpace(role.Name)
	if tenantID == "" || roleName == "" {
		return domain.ErrInvalidArgument
	}
	role.Name = roleName
	data, err := json.Marshal(role)
	if err != nil {
		return err
	}
	return r.client.HSet(ctx, rolesKey(tenantID), roleName, data).Err()
}

func (r *roleRepo) CreateIfAbsent(ctx context.Context, tenantID string, role *domain.Role) (*domain.Role, bool, error) {
	if tenantID == "" || role == nil || role.Name == "" {
		return nil, false, domain.ErrInvalidArgument
	}
	data, err := json.Marshal(role)
	if err != nil {
		return nil, false, err
	}
	created, err := r.client.HSetNX(ctx, rolesKey(tenantID), role.Name, data).Result()
	if err != nil {
		return nil, false, err
	}
	if created {
		return role, true, nil
	}
	stored, err := r.Get(ctx, tenantID, role.Name)
	return stored, false, err
}

func (r *roleRepo) Get(ctx context.Context, tenantID string, name string) (*domain.Role, error) {
	val, err := r.client.HGet(ctx, rolesKey(tenantID), name).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if val == "" {
		return nil, nil
	}
	var role domain.Role
	if e := json.Unmarshal([]byte(val), &role); e != nil {
		return nil, e
	}
	return &role, nil
}

func (r *roleRepo) List(ctx context.Context, tenantID string) ([]*domain.Role, error) {
	vals, err := r.client.HGetAll(ctx, rolesKey(tenantID)).Result()
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Role, 0, len(vals))
	for _, v := range vals {
		var role domain.Role
		if e := json.Unmarshal([]byte(v), &role); e != nil {
			return nil, e
		}
		out = append(out, &role)
	}
	return out, nil
}

func rolesKey(tenantID string) string {
	return "roles:" + tenantID
}
