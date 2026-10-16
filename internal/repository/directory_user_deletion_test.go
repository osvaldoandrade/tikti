package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v8"
	rkeys "github.com/osvaldoandrade/tikti/internal/redis"
	"github.com/vmihailenco/msgpack/v5"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/testredis"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestDirectoryUserPublicVersionTracksSecurityRevision(t *testing.T) {
	_, directory := newIdentityDirectoryForTest(t)
	user := &domain.User{
		Id: "versioned-user", Email: "versioned@example.com", Password: "hash",
		Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive,
		AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now().UTC(),
	}
	for expected := int64(1); expected <= 2; expected++ {
		var projected *domain.DirectoryUser
		var err error
		if expected == 1 {
			projected, err = directory.CreateDirectoryUser(context.Background(), user)
		} else {
			user.Status = domain.UserStatusSuspended
			projected, err = directory.UpdateDirectoryUser(context.Background(), user)
		}
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(projected)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(payload, &fields)
		var version int64
		_ = json.Unmarshal(fields["version"], &version)
		if version != expected {
			t.Fatalf("public version = %d, want %d", version, expected)
		}
	}
}

func newDeletionUsers(t *testing.T, clients ...*redis.Client) (*redis.Client, IdentityDirectoryRepository, domain.DirectoryDeletionActor, *domain.User) {
	t.Helper()
	client, directory := newIdentityDirectoryForTest(t)
	if len(clients) == 1 {
		client = clients[0]
		directory = NewIdentityDirectoryRepository(client)
	}
	client.Set(context.Background(), directoryBackfillMarker, directoryBackfillVersion, 0)
	actor := &domain.User{Id: "actor-admin", Email: "actor@example.com", Password: "hash", Role: domain.RoleAdmin, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now().UTC()}
	target := &domain.User{Id: "target-user", Email: "target@example.com", Password: "hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now().UTC()}
	for _, user := range []*domain.User{actor, target} {
		if _, err := directory.CreateDirectoryUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
	}
	return client, directory, domain.DirectoryDeletionActor{UserID: actor.Id}, target
}

func TestDirectoryUserDeletionRemovesOwnedRelationshipsOnly(t *testing.T) {
	client, directory, actor, target := newDeletionUsers(t)
	ctx := context.Background()
	group, err := directory.CreateGroup(ctx, "shared group", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = directory.PutGroupMember(ctx, group.ID, target.Id, "*"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = directory.PutGroupMember(ctx, group.ID, actor.UserID, "*"); err != nil {
		t.Fatal(err)
	}
	before, err := directory.GetGroup(ctx, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = directory.PutAccessAssignment(ctx, "conveste", domain.AccessPrincipalUser, target.Id, []string{"reader"}, "*"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = directory.PutAccessAssignment(ctx, "conveste", domain.AccessPrincipalUser, actor.UserID, []string{"reader"}, "*"); err != nil {
		t.Fatal(err)
	}
	legacy := &domain.Membership{Id: "legacy-member", TenantId: "legacy-tenant", UserId: target.Id, Roles: []string{"reader"}, CreatedAt: time.Now().UTC()}
	if err = NewMembershipRepo(client).Create(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	v2 := &domain.Membership{Id: membershipV2ID("v2-tenant", target.Id), TenantId: "v2-tenant", UserId: target.Id, Roles: []string{"reader"}, CreatedAt: time.Now().UTC()}
	raw, _ := json.Marshal(v2)
	for _, key := range []string{membershipsKey(v2.TenantId), membershipV2Key(v2.TenantId)} {
		client.HSet(ctx, key, target.Id, raw)
	}
	client.SAdd(ctx, membershipsByUserPrefix+target.Id, v2.TenantId)
	client.SAdd(ctx, membershipV2ByUserKey(target.Id), v2.TenantId)
	raw, _ = json.Marshal(target)
	client.HSet(ctx, legacyUsersHash, target.Email, raw)
	client.Set(ctx, "workload:preserved", "workload", 0)
	client.Set(ctx, "audit:preserved", "event", 0)
	deleted, err := directory.DeleteDirectoryUser(ctx, target.Id, 1, actor)
	if err != nil || !deleted {
		t.Fatalf("delete=%v err=%v", deleted, err)
	}
	for _, key := range []string{userByEmailKeyNS + target.Email, userGroupsKey(target.Id), principalTenantsKey(domain.AccessPrincipalUser, target.Id), membershipsByUserPrefix + target.Id, membershipV2ByUserKey(target.Id)} {
		if client.Exists(ctx, key).Val() != 0 {
			t.Errorf("owned key remains: %s", key)
		}
	}
	if client.HExists(ctx, usersHashV2, target.Id).Val() || client.HExists(ctx, legacyUsersHash, target.Email).Val() || client.HExists(ctx, assignmentsKey("conveste"), assignmentField(domain.AccessPrincipalUser, target.Id)).Val() {
		t.Fatal("target authority remains")
	}
	for _, key := range []string{membershipsKey("legacy-tenant"), membershipsKey("v2-tenant"), membershipV2Key("v2-tenant")} {
		if client.HExists(ctx, key, target.Id).Val() {
			t.Errorf("membership remains in %s", key)
		}
	}
	after, err := directory.GetGroup(ctx, group.ID)
	if err != nil || after.Version != before.Version+1 || after.MemberCount != 1 || !client.SIsMember(ctx, groupMembersKey(group.ID), actor.UserID).Val() {
		t.Fatalf("group after=%#v err=%v", after, err)
	}
	if !client.HExists(ctx, assignmentsKey("conveste"), assignmentField(domain.AccessPrincipalUser, actor.UserID)).Val() || client.Exists(ctx, "workload:preserved", "audit:preserved").Val() != 2 {
		t.Fatal("unrelated authority or data changed")
	}
	if deleted, err = directory.DeleteDirectoryUser(ctx, target.Id, 1, actor); err != nil || deleted {
		t.Fatalf("repeat delete=%v err=%v", deleted, err)
	}
}

func TestDirectoryUserDeletionRejectsStaleActorAndTarget(t *testing.T) {
	for _, scenario := range []string{"stale target", "self", "suspended actor", "demoted actor", "revoked actor", "changed actor", "absent actor", "duplicate actor", "recovered missing", "recovered foreign role", "recovered missing reverse"} {
		t.Run(scenario, func(t *testing.T) {
			client, directory, actor, target := newDeletionUsers(t)
			ctx := context.Background()
			version := int64(1)
			want := domain.ErrDirectoryDeletionDenied
			stored, _ := NewRedisRepo(client).(UserIDRepository).FindByID(ctx, actor.UserID)
			switch scenario {
			case "stale target":
				version = 2
				want = domain.ErrVersionConflict
			case "self":
				target.Id = actor.UserID
			case "suspended actor":
				stored.Status = domain.UserStatusSuspended
			case "demoted actor":
				stored.Role = domain.RoleCompanyAdmin
			case "revoked actor":
				stored.TokenVersion++
			case "changed actor":
				stored.Revision++
			case "absent actor":
				client.HDel(ctx, usersHashV2, actor.UserID)
			case "duplicate actor":
				raw, _ := json.Marshal(stored)
				client.HSet(ctx, federatedUsersHash, actor.UserID, raw)
				want = domain.ErrDirectoryInvariant
			default:
				actor.RecoveredMaster = true
				stored.CompanyId = stringPointer("conveste")
				if scenario != "recovered missing" {
					roles := []string{"ADMIN"}
					if scenario == "recovered foreign role" {
						roles = []string{"reader"}
					}
					if _, _, err := directory.PutAccessAssignment(ctx, domain.MasterTenantID, domain.AccessPrincipalUser, actor.UserID, roles, "*"); err != nil {
						t.Fatal(err)
					}
					if scenario == "recovered missing reverse" {
						client.Del(ctx, principalTenantsKey(domain.AccessPrincipalUser, actor.UserID))
					}
				}
			}
			if scenario != "absent actor" && scenario != "duplicate actor" {
				raw, _ := json.Marshal(stored)
				client.HSet(ctx, usersHashV2, actor.UserID, raw)
			}
			if deleted, err := directory.DeleteDirectoryUser(ctx, target.Id, version, actor); deleted || !errors.Is(err, want) {
				t.Fatalf("delete=%v err=%v want=%v", deleted, err, want)
			}
			if !client.HExists(ctx, usersHashV2, target.Id).Val() {
				t.Fatal("rejected deletion changed target")
			}
		})
	}
}

func TestDirectoryUserDeletionRecoveredMasterAuthority(t *testing.T) {
	client, directory, actor, target := newDeletionUsers(t)
	ctx := context.Background()
	stored, _ := NewRedisRepo(client).(UserIDRepository).FindByID(ctx, actor.UserID)
	stored.CompanyId = stringPointer("conveste")
	raw, _ := json.Marshal(stored)
	client.HSet(ctx, usersHashV2, actor.UserID, raw)
	if _, _, err := directory.PutAccessAssignment(ctx, domain.MasterTenantID, domain.AccessPrincipalUser, actor.UserID, []string{"ADMIN"}, "*"); err != nil {
		t.Fatal(err)
	}
	actor.RecoveredMaster = true
	if deleted, err := directory.DeleteDirectoryUser(ctx, target.Id, 1, actor); err != nil || !deleted {
		t.Fatalf("delete=%v err=%v", deleted, err)
	}
}

func TestDirectoryUserDeletionSAMLSharedEmailIsolation(t *testing.T) {
	for _, federated := range []bool{false, true} {
		t.Run(fmt.Sprint(federated), func(t *testing.T) {
			client, directory, actor, target := newDeletionUsers(t)
			ctx := context.Background()
			samlUser := &domain.User{Id: "saml-target", Email: target.Email, Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourceSAML, CompanyId: stringPointer("conveste"), ExternalSubject: "external-target", CreatedAt: time.Now().UTC(), Revision: 3}
			hash := federatedUsersHash
			if !federated {
				hash = usersHashV2
				samlUser.Email = "saml-global@example.com"
				client.Set(ctx, userByEmailKeyNS+samlUser.Email, samlUser.Id, 0)
				client.ZAdd(ctx, directoryUserEmailIndex, &redis.Z{Member: directoryUserIndexMember(samlUser.Email, samlUser.Id)})
			}
			raw, _ := json.Marshal(samlUser)
			client.HSet(ctx, hash, samlUser.Id, raw)
			client.Set(ctx, samlSubjectKey("conveste", samlUser.ExternalSubject), samlUser.Id, 0)
			record := rkeys.SAMLSessionIndexRecord{TenantID: "conveste", Subject: samlUser.Id, NameID: samlUser.ExternalSubject, Email: samlUser.Email, SessionIndex: "session", NotOnOrAfter: time.Now().Add(time.Hour)}
			indexRaw, _ := msgpack.Marshal(record)
			subjectKey := rkeys.SAMLIndexPrefix + rkeys.SAMLSessionIndexKey("conveste", "subject", samlUser.Id)
			nameKey := rkeys.SAMLIndexPrefix + rkeys.SAMLSessionIndexKey("conveste", "nameid", samlUser.ExternalSubject)
			client.Set(ctx, subjectKey, indexRaw, time.Hour)
			client.Set(ctx, nameKey, indexRaw, time.Hour)
			projected, err := directory.GetDirectoryUser(ctx, samlUser.Id)
			if err != nil || projected == nil || projected.Version != 4 {
				t.Fatalf("SAML exact projection=%#v err=%v", projected, err)
			}
			if deleted, err := directory.DeleteDirectoryUser(ctx, samlUser.Id, 4, actor); err != nil || !deleted {
				t.Fatalf("delete=%v err=%v", deleted, err)
			}
			if client.Exists(ctx, subjectKey, nameKey, samlSubjectKey("conveste", samlUser.ExternalSubject)).Val() != 0 || client.HExists(ctx, hash, samlUser.Id).Val() {
				t.Fatal("SAML authority remains")
			}
			other, err := NewRedisRepo(client).FindByEmail(ctx, target.Email)
			if err != nil || other == nil || other.Id != target.Id {
				t.Fatalf("same email owner=%#v err=%v", other, err)
			}
		})
	}
}

func TestDirectoryUserDeletionCorruptionHasNoPartialEffects(t *testing.T) {
	for _, scenario := range []string{"duplicate subject", "duplicate json field", "foreign email alias", "invalid order type", "foreign assignment", "missing group reverse", "oversized reverse", "malformed group"} {
		t.Run(scenario, func(t *testing.T) {
			client, directory, actor, target := newDeletionUsers(t)
			ctx := context.Background()
			switch scenario {
			case "duplicate subject":
				raw, _ := json.Marshal(target)
				client.HSet(ctx, federatedUsersHash, target.Id, raw)
			case "duplicate json field":
				raw, _ := json.Marshal(target)
				raw = append(raw[:len(raw)-1], []byte(`,"localId":"target-user"}`)...)
				client.HSet(ctx, usersHashV2, target.Id, raw)
			case "foreign email alias":
				client.Set(ctx, userByEmailKeyNS+target.Email, actor.UserID, 0)
			case "invalid order type":
				client.Del(ctx, directoryUserEmailIndex)
				client.Set(ctx, directoryUserEmailIndex, "invalid", 0)
			case "foreign assignment":
				client.SAdd(ctx, principalTenantsKey(domain.AccessPrincipalUser, target.Id), "conveste")
				client.HSet(ctx, assignmentsKey("conveste"), assignmentField(domain.AccessPrincipalUser, target.Id), `{"principalId":"other"}`)
			case "missing group reverse":
				client.SAdd(ctx, userGroupsKey(target.Id), "grp_missing")
			case "oversized reverse":
				for i := 0; i <= directoryMaximumRelationships; i++ {
					client.SAdd(ctx, userGroupsKey(target.Id), fmt.Sprintf("grp_%03d", i))
				}
			case "malformed group":
				client.SAdd(ctx, userGroupsKey(target.Id), "grp_corrupt")
				client.SAdd(ctx, groupMembersKey("grp_corrupt"), target.Id)
				client.HSet(ctx, directoryGroupsHash, "grp_corrupt", "invalid")
			}
			before := redisSnapshot(t, client)
			if deleted, err := directory.DeleteDirectoryUser(ctx, target.Id, 1, actor); err == nil || deleted {
				t.Fatalf("delete=%v err=%v", deleted, err)
			}
			if after := redisSnapshot(t, client); !reflect.DeepEqual(before, after) {
				t.Fatal("rejected delete partially mutated storage")
			}
		})
	}
}

func redisSnapshot(t *testing.T, client *redis.Client) map[string]string {
	t.Helper()
	ctx := context.Background()
	keys, err := client.Keys(ctx, "*").Result()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := make(map[string]string, len(keys))
	for _, key := range keys {
		var value any
		switch client.Type(ctx, key).Val() {
		case "string":
			value = client.Get(ctx, key).Val()
		case "hash":
			value = client.HGetAll(ctx, key).Val()
		case "set":
			members := client.SMembers(ctx, key).Val()
			sort.Strings(members)
			value = members
		case "zset":
			value = client.ZRangeWithScores(ctx, key, 0, -1).Val()
		default:
			t.Fatalf("unexpected snapshot type for %s", key)
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		snapshot[key] = string(raw)
	}
	return snapshot
}

func TestDirectoryUserConcurrentCrossDeletionKeepsOneAdministrator(t *testing.T) {
	server, err := testredis.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	client, directory, actor, target := newDeletionUsers(t, server.Client)
	ctx := context.Background()
	target.Role = domain.RoleAdmin
	raw, _ := json.Marshal(target)
	client.HSet(ctx, usersHashV2, target.Id, raw)
	other := domain.DirectoryDeletionActor{UserID: target.Id}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, operation := range []struct {
		actor  domain.DirectoryDeletionActor
		target string
	}{{actor, target.Id}, {other, actor.UserID}} {
		go func() {
			<-start
			_, err := directory.DeleteDirectoryUser(ctx, operation.target, 1, operation.actor)
			results <- err
		}()
	}
	close(start)
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("cross delete errors=%v,%v", first, second)
	}
	if client.HLen(ctx, usersHashV2).Val() != 1 {
		t.Fatal("both administrators deleted")
	}
}
