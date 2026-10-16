package repository

import (
	"context"
	"encoding/json"

	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// importLegacyEmailUser is available only before startup migration completes.
// WATCH prevents an in-flight legacy read from reintroducing a deleted subject.
func (r *redisRepo) importLegacyEmailUser(ctx context.Context, email string) (*domain.User, error) {
	var result *domain.User
	err := r.client.Watch(ctx, func(tx *redis.Tx) error {
		marker, err := tx.Get(ctx, directoryBackfillMarker).Result()
		if err == nil {
			if marker != directoryBackfillVersion {
				return domain.ErrDirectoryInvariant
			}
			return nil
		}
		if err != redis.Nil {
			return err
		}
		if _, err = tx.Get(ctx, userByEmailKeyNS+email).Result(); err == nil {
			return redis.TxFailedErr
		} else if err != redis.Nil {
			return err
		}
		raw, err := tx.HGet(ctx, legacyUsersHash, email).Result()
		if err == redis.Nil {
			return nil
		}
		if err != nil {
			return err
		}
		var legacy domain.User
		if err = json.Unmarshal([]byte(raw), &legacy); err != nil {
			return err
		}
		if legacy.Password == "" && legacy.AuthSource != domain.AuthSourceSAML {
			return domain.ErrNotFound
		}
		canonical, err := canonicalDirectoryStorageUser(&legacy)
		if err != nil || canonical.Email != email {
			return domain.ErrDirectoryInvariant
		}
		for _, hash := range []string{usersHashV2, federatedUsersHash} {
			exists, err := tx.HExists(ctx, hash, canonical.Id).Result()
			if err != nil {
				return err
			}
			if exists {
				return domain.ErrDirectoryInvariant
			}
		}
		if _, err = tx.ZScore(ctx, directoryUserEmailIndex, directoryUserIndexMember(email, canonical.Id)).Result(); err != nil && err != redis.Nil {
			return err
		}
		// #nosec G117 -- the legacy payload contains only the existing password hash.
		payload, err := json.Marshal(canonical)
		if err != nil {
			return domain.ErrDirectoryInvariant
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.HSet(ctx, usersHashV2, canonical.Id, payload)
			pipe.Set(ctx, userByEmailKeyNS+email, canonical.Id, 0)
			pipe.ZAdd(ctx, directoryUserEmailIndex, &redis.Z{Member: directoryUserIndexMember(email, canonical.Id)})
			return nil
		})
		if err == nil {
			result = canonical
		}
		return err
	}, directoryBackfillMarker, usersHashV2, federatedUsersHash, userByEmailKeyNS+email, legacyUsersHash, directoryUserEmailIndex)
	return result, err
}
