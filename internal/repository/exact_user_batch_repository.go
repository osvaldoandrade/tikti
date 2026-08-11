package repository

import (
	"context"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// ExactUserBatchRepository preserves GetExact validation while bounding a
// membership page to one user-document read and one email-index read.
type ExactUserBatchRepository interface {
	GetManyExact(ctx context.Context, userIDs []string) ([]domain.UserIdentity, error)
}

func (r *redisRepo) GetManyExact(ctx context.Context, userIDs []string) ([]domain.UserIdentity, error) {
	if r == nil || r.client == nil || len(userIDs) > exactMembershipListPageMax {
		return nil, domain.ErrInvalidArgument
	}
	identities := make([]domain.UserIdentity, len(userIDs))
	if len(userIDs) == 0 {
		return identities, nil
	}
	for _, userID := range userIDs {
		if !canonicalUserIdentity(userID) {
			return nil, domain.ErrInvalidArgument
		}
	}
	values, err := r.client.HMGet(ctx, usersHashV2, userIDs...).Result()
	if err != nil || len(values) != len(userIDs) {
		return nil, errStoredUserContract
	}
	indexKeys := make([]string, len(userIDs))
	for index, raw := range values {
		value, ok := raw.(string)
		identity, email, valid := decodeExactUserIdentity(value, userIDs[index])
		if !ok || !valid {
			return nil, errStoredUserContract
		}
		identities[index] = *identity
		indexKeys[index] = userByEmailKeyNS + email
	}
	indexes, err := r.client.MGet(ctx, indexKeys...).Result()
	if err != nil || len(indexes) != len(userIDs) {
		return nil, errStoredUserContract
	}
	for index, raw := range indexes {
		indexedID, ok := raw.(string)
		if !ok || indexedID != userIDs[index] {
			return nil, errStoredUserContract
		}
	}
	return identities, nil
}
