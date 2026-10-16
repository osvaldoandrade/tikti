package repository

import (
	"context"
	"encoding/json"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vmihailenco/msgpack/v5"

	rkeys "github.com/osvaldoandrade/tikti/internal/redis"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// DeleteDirectoryUser deletes only the immutable subject and its owned identity
// links. Actor and target authority are checked in the same Redis transaction.
func (r *identityDirectoryRepo) DeleteDirectoryUser(ctx context.Context, userID string, version int64, actor domain.DirectoryDeletionActor) (bool, error) {
	if r == nil || r.client == nil || !canonicalUserIdentity(userID) || version < 1 {
		return false, domain.ErrInvalidArgument
	}
	if !canonicalUserIdentity(actor.UserID) || actor.UserID == userID || actor.TokenVersion < 0 || actor.Revision < 0 {
		return false, domain.ErrDirectoryDeletionDenied
	}
	base := []string{usersHashV2, federatedUsersHash, directoryGroupsHash, directoryBackfillMarker,
		userGroupsKey(userID), principalTenantsKey(domain.AccessPrincipalUser, userID),
		membershipsByUserPrefix + userID, membershipV2ByUserKey(userID)}
	if actor.RecoveredMaster {
		base = append(base, assignmentsKey(domain.MasterTenantID), principalTenantsKey(domain.AccessPrincipalUser, actor.UserID))
	}
	for attempt := 0; attempt < directoryMaximumRetries; attempt++ {
		deleted := false
		err := r.client.Watch(ctx, func(tx *redis.Tx) error {
			if err := validateDeletionActor(ctx, tx, actor); err != nil {
				return err
			}
			marker, err := tx.Get(ctx, directoryBackfillMarker).Result()
			if err != nil {
				return err
			}
			if marker != directoryBackfillVersion {
				return domain.ErrDirectoryInvariant
			}
			target, hash, err := deletionStorageUser(ctx, tx, userID)
			if err != nil {
				return err
			}
			if target == nil {
				// EXEC gives even the absent-target response one authority linearization point.
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error { pipe.Ping(ctx); return nil })
				return err
			}
			if target.Revision+1 != version {
				return domain.ErrVersionConflict
			}
			plan, err := prepareUserDeletion(ctx, tx, target, hash)
			if err != nil {
				return err
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				plan.apply(ctx, pipe)
				return nil
			})
			deleted = err == nil
			return err
		}, base...)
		if err != redis.TxFailedErr {
			return deleted, err
		}
	}
	return false, errDirectoryRetry
}

func deletionStorageUser(ctx context.Context, tx redis.Cmdable, userID string) (*domain.User, string, error) {
	var found *domain.User
	var owner string
	for _, hash := range []string{usersHashV2, federatedUsersHash} {
		raw, err := tx.HGet(ctx, hash, userID).Result()
		if err == redis.Nil {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		if found != nil {
			return nil, "", domain.ErrDirectoryInvariant
		}
		user, err := decodeDeletionUser(raw, userID, hash)
		if err != nil {
			return nil, "", err
		}
		found, owner = user, hash
	}
	return found, owner, nil
}

func decodeDeletionUser(raw, userID, hash string) (*domain.User, error) {
	var user domain.User
	allowed := fields("localId", "email", "password", "role", "status", "companyId", "tokenVersion", "revision", "createdAt", "authSource", "externalSubject", "passwordChangeRequired")
	if len(raw) == 0 || len(raw) > 16<<10 || !decodeExactObject(raw, allowed, &user) || user.Id != userID || user.TokenVersion < 0 ||
		user.Revision < 0 || user.Revision == math.MaxInt64 || user.CreatedAt.IsZero() || !validUserStatus(user.Status) ||
		user.Role != domain.RoleAdmin && user.Role != domain.RoleCompanyAdmin && user.Role != domain.RoleCompanyEmployee {
		return nil, domain.ErrDirectoryInvariant
	}
	var canonical *domain.User
	var err error
	if hash == federatedUsersHash {
		canonical, err = canonicalFederatedUser(&user)
	} else {
		canonical, err = canonicalDirectoryStorageUser(&user)
	}
	if err != nil || canonical.Email != user.Email || canonical.AuthSource != user.AuthSource {
		return nil, domain.ErrDirectoryInvariant
	}
	return canonical, nil
}

func validateDeletionActor(ctx context.Context, tx *redis.Tx, actor domain.DirectoryDeletionActor) error {
	user, _, err := deletionStorageUser(ctx, tx, actor.UserID)
	if err != nil {
		return err
	}
	if user == nil || user.Status != domain.UserStatusActive || user.Role != domain.RoleAdmin ||
		user.PasswordChangeRequired || user.TokenVersion != actor.TokenVersion || user.Revision != actor.Revision {
		return domain.ErrDirectoryDeletionDenied
	}
	if !actor.RecoveredMaster {
		return nil
	}
	if user.AuthSource != domain.AuthSourcePassword || user.CompanyId == nil || *user.CompanyId == domain.MasterTenantID {
		return domain.ErrDirectoryDeletionDenied
	}
	raw, err := tx.HGet(ctx, assignmentsKey(domain.MasterTenantID), assignmentField(domain.AccessPrincipalUser, user.Id)).Result()
	if err == redis.Nil {
		return domain.ErrDirectoryDeletionDenied
	}
	if err != nil {
		return err
	}
	assignment, err := decodeAssignment(raw, domain.MasterTenantID, domain.AccessPrincipalUser, user.Id)
	if err != nil {
		return err
	}
	reverse, err := tx.SIsMember(ctx, principalTenantsKey(domain.AccessPrincipalUser, user.Id), domain.MasterTenantID).Result()
	if err != nil {
		return err
	}
	if !reverse || !slices.Equal(assignment.Roles, []string{string(domain.RoleAdmin)}) {
		return domain.ErrDirectoryDeletionDenied
	}
	return nil
}

type userDeletionPlan struct {
	user          *domain.User
	hash          string
	keys          []string
	legacy        bool
	groups        map[string][]byte
	assignments   []string
	legacyTenants []string
	v2Tenants     []string
}

func prepareUserDeletion(ctx context.Context, tx *redis.Tx, user *domain.User, hash string) (*userDeletionPlan, error) {
	plan := &userDeletionPlan{user: user, hash: hash, groups: make(map[string][]byte)}
	groups, err := deletionBoundedSet(ctx, tx, userGroupsKey(user.Id))
	if err != nil {
		return nil, err
	}
	plan.assignments, err = deletionBoundedSet(ctx, tx, principalTenantsKey(domain.AccessPrincipalUser, user.Id))
	if err != nil {
		return nil, err
	}
	plan.legacyTenants, err = deletionBoundedSet(ctx, tx, membershipsByUserPrefix+user.Id)
	if err != nil {
		return nil, err
	}
	plan.v2Tenants, err = deletionBoundedSet(ctx, tx, membershipV2ByUserKey(user.Id))
	if err != nil {
		return nil, err
	}
	if len(groups)+len(plan.assignments)+len(plan.legacyTenants)+len(plan.v2Tenants) > directoryMaximumRelationships {
		return nil, domain.ErrDirectoryInvariant
	}
	if err = plan.prepareAliases(ctx, tx); err != nil {
		return nil, err
	}
	if err = plan.prepareGroups(ctx, tx, groups); err != nil {
		return nil, err
	}
	if err = plan.prepareAssignments(ctx, tx); err != nil {
		return nil, err
	}
	if err = plan.prepareMemberships(ctx, tx); err != nil {
		return nil, err
	}
	if err = plan.prepareSAML(ctx, tx); err != nil {
		return nil, err
	}
	return plan, nil
}

func deletionBoundedSet(ctx context.Context, tx *redis.Tx, key string) ([]string, error) {
	count, err := tx.SCard(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if count > directoryMaximumRelationships {
		return nil, domain.ErrDirectoryInvariant
	}
	members, err := tx.SMembers(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if len(members) > directoryMaximumRelationships {
		return nil, domain.ErrDirectoryInvariant
	}
	sort.Strings(members)
	return members, nil
}

func (p *userDeletionPlan) prepareAliases(ctx context.Context, tx *redis.Tx) error {
	emailKey := userByEmailKeyNS + p.user.Email
	if err := tx.Watch(ctx, emailKey, directoryUserEmailIndex, legacyUsersHash).Err(); err != nil {
		return err
	}
	if _, err := tx.ZScore(ctx, directoryUserEmailIndex, directoryUserIndexMember(p.user.Email, p.user.Id)).Result(); err != nil && err != redis.Nil {
		return err
	}
	owner, err := tx.Get(ctx, emailKey).Result()
	if err != nil && err != redis.Nil {
		return err
	}
	if err == nil {
		if owner == p.user.Id {
			p.keys = append(p.keys, emailKey)
		} else if p.hash == usersHashV2 {
			return domain.ErrDirectoryInvariant
		}
	}
	raw, err := tx.HGet(ctx, legacyUsersHash, p.user.Email).Result()
	if err == redis.Nil {
		return nil
	}
	if err != nil {
		return err
	}
	var legacy domain.User
	if !decodeExactObject(raw, fields("localId", "email", "password", "role", "status", "companyId", "tokenVersion", "revision", "createdAt", "authSource", "externalSubject", "passwordChangeRequired"), &legacy) || legacy.Id == "" {
		return domain.ErrDirectoryInvariant
	}
	if legacy.Id == p.user.Id {
		canonical, err := canonicalDirectoryStorageUser(&legacy)
		if err != nil || canonical.Email != p.user.Email {
			return domain.ErrDirectoryInvariant
		}
		p.legacy = true
	}
	return nil
}

func (p *userDeletionPlan) prepareGroups(ctx context.Context, tx *redis.Tx, groups []string) error {
	for _, groupID := range groups {
		if !canonicalGroupID(groupID) {
			return domain.ErrDirectoryInvariant
		}
		if err := tx.Watch(ctx, groupMembersKey(groupID)).Err(); err != nil {
			return err
		}
		present, err := tx.SIsMember(ctx, groupMembersKey(groupID), p.user.Id).Result()
		if err != nil {
			return err
		}
		if !present {
			return domain.ErrDirectoryInvariant
		}
		raw, err := tx.HGet(ctx, directoryGroupsHash, groupID).Result()
		if err != nil {
			return domain.ErrDirectoryInvariant
		}
		group, err := decodeGroup(raw, groupID)
		if err != nil || group.Version == math.MaxInt64 {
			return domain.ErrDirectoryInvariant
		}
		group.Version++
		group.UpdatedAt = time.Now().UTC()
		p.groups[groupID], err = json.Marshal(group)
		if err != nil {
			return domain.ErrDirectoryInvariant
		}
	}
	return nil
}

func (p *userDeletionPlan) prepareAssignments(ctx context.Context, tx *redis.Tx) error {
	for _, tenant := range p.assignments {
		if !activeTenantIdentity(tenant) {
			return domain.ErrDirectoryInvariant
		}
		if err := tx.Watch(ctx, assignmentsKey(tenant)).Err(); err != nil {
			return err
		}
		raw, err := tx.HGet(ctx, assignmentsKey(tenant), assignmentField(domain.AccessPrincipalUser, p.user.Id)).Result()
		if err != nil {
			return domain.ErrDirectoryInvariant
		}
		if _, err = decodeAssignment(raw, tenant, domain.AccessPrincipalUser, p.user.Id); err != nil {
			return err
		}
	}
	return nil
}

func (p *userDeletionPlan) prepareMemberships(ctx context.Context, tx *redis.Tx) error {
	for _, tenant := range p.legacyTenants {
		if !canonicalTenantIdentity(tenant) {
			return domain.ErrDirectoryInvariant
		}
		if err := tx.Watch(ctx, membershipsKey(tenant)).Err(); err != nil {
			return err
		}
		raw, err := tx.HGet(ctx, membershipsKey(tenant), p.user.Id).Result()
		if err != nil {
			return domain.ErrDirectoryInvariant
		}
		membership, valid := decodeExactMembership(raw)
		if !valid || membership.UserId != p.user.Id || membership.TenantId != tenant {
			return domain.ErrDirectoryInvariant
		}
	}
	for _, tenant := range p.v2Tenants {
		if !canonicalTenantIdentity(tenant) || !slices.Contains(p.legacyTenants, tenant) {
			return domain.ErrDirectoryInvariant
		}
		if err := tx.Watch(ctx, membershipV2Key(tenant)).Err(); err != nil {
			return err
		}
		raw, err := tx.HGet(ctx, membershipV2Key(tenant), p.user.Id).Result()
		if err != nil {
			return domain.ErrDirectoryInvariant
		}
		if _, valid := decodeMembershipV2(tenant, p.user.Id, raw); !valid {
			return domain.ErrDirectoryInvariant
		}
		legacy, err := tx.HGet(ctx, membershipsKey(tenant), p.user.Id).Result()
		if err != nil || legacy != raw {
			return domain.ErrDirectoryInvariant
		}
	}
	return nil
}

func (p *userDeletionPlan) prepareSAML(ctx context.Context, tx *redis.Tx) error {
	if p.user.AuthSource != domain.AuthSourceSAML {
		return nil
	}
	if p.user.CompanyId == nil || !activeTenantIdentity(*p.user.CompanyId) {
		return domain.ErrDirectoryInvariant
	}
	tenant := *p.user.CompanyId
	alias := samlSubjectKey(tenant, p.user.ExternalSubject)
	if err := tx.Watch(ctx, alias).Err(); err != nil {
		return err
	}
	owner, err := tx.Get(ctx, alias).Result()
	if err != nil && err != redis.Nil {
		return err
	}
	if err == nil {
		if owner != p.user.Id {
			return domain.ErrDirectoryInvariant
		}
		p.keys = append(p.keys, alias)
	}
	subjectKey := rkeys.SAMLIndexPrefix + rkeys.SAMLSessionIndexKey(tenant, "subject", p.user.Id)
	record, found, err := p.ownedSessionIndex(ctx, tx, subjectKey)
	if err != nil {
		return err
	}
	nameID := p.user.ExternalSubject
	if found {
		nameID = record.NameID
	}
	nameAlias := rkeys.SAMLSessionIndexKey(tenant, "nameid", nameID)
	if nameAlias == "" {
		return domain.ErrDirectoryInvariant
	}
	nameKey := rkeys.SAMLIndexPrefix + nameAlias
	_, _, err = p.ownedSessionIndex(ctx, tx, nameKey)
	return err
}

func (p *userDeletionPlan) ownedSessionIndex(ctx context.Context, tx *redis.Tx, key string) (rkeys.SAMLSessionIndexRecord, bool, error) {
	var record rkeys.SAMLSessionIndexRecord
	if err := tx.Watch(ctx, key).Err(); err != nil {
		return record, false, err
	}
	raw, err := tx.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if msgpack.Unmarshal(raw, &record) != nil || record.TenantID != *p.user.CompanyId || record.Subject != p.user.Id ||
		record.NameID == "" || record.SessionIndex == "" || record.Email == "" ||
		key != rkeys.SAMLIndexPrefix+rkeys.SAMLSessionIndexKey(record.TenantID, "subject", record.Subject) &&
			key != rkeys.SAMLIndexPrefix+rkeys.SAMLSessionIndexKey(record.TenantID, "nameid", record.NameID) {
		return record, false, domain.ErrDirectoryInvariant
	}
	p.keys = append(p.keys, key)
	return record, true, nil
}

func (p *userDeletionPlan) apply(ctx context.Context, pipe redis.Pipeliner) {
	userID := p.user.Id
	pipe.HDel(ctx, p.hash, userID)
	pipe.Del(ctx, userGroupsKey(userID), principalTenantsKey(domain.AccessPrincipalUser, userID), membershipsByUserPrefix+userID, membershipV2ByUserKey(userID))
	if len(p.keys) != 0 {
		pipe.Del(ctx, p.keys...)
	}
	pipe.ZRem(ctx, directoryUserEmailIndex, directoryUserIndexMember(p.user.Email, userID))
	if p.legacy {
		pipe.HDel(ctx, legacyUsersHash, p.user.Email)
	}
	for groupID, raw := range p.groups {
		pipe.SRem(ctx, groupMembersKey(groupID), userID)
		pipe.HSet(ctx, directoryGroupsHash, groupID, raw)
	}
	for _, tenant := range p.assignments {
		pipe.HDel(ctx, assignmentsKey(tenant), assignmentField(domain.AccessPrincipalUser, userID))
	}
	for _, tenant := range p.legacyTenants {
		pipe.HDel(ctx, membershipsKey(tenant), userID)
	}
	for _, tenant := range p.v2Tenants {
		pipe.HDel(ctx, membershipV2Key(tenant), userID)
	}
}
