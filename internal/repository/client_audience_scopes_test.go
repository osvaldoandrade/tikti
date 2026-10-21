package repository

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestClientRepoReconcileExistingAudienceScopesCAS(t *testing.T) {
	for _, owner := range []string{"bootstrap-home", "managed"} {
		for _, change := range []string{"none", "changed client", "deleted client", "changed owner marker"} {
			t.Run(owner+"/"+change, func(t *testing.T) {
				ctx := context.Background()
				redisClient, repo := newClientRepoForTest(t)
				hook := &rejectEvalSHAHook{}
				redisClient.AddHook(hook)
				t.Cleanup(func() {
					if hook.calls != 0 {
						t.Errorf("audience reconciliation depended on %d EVALSHA commands", hook.calls)
					}
				})
				current := &domain.Client{Id: domain.CodeAdminAudienceClientID, TenantId: domain.MasterTenantID,
					Type: domain.ClientTypePublic, Status: domain.ClientStatusActive,
					AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)}, DefaultScopes: []string{"code-admin:logs:read"}}
				if owner == "managed" {
					current.Type, current.ManagedBy = domain.ClientTypeService, domain.CodeAdminAudienceClientManager
					if _, _, err := repo.EnsureManagedAudience(ctx, current.TenantId, current); err != nil {
						t.Fatal(err)
					}
				} else if err := repo.UpsertBootstrap(ctx, current.TenantId, current); err != nil {
					t.Fatal(err)
				}
				key, marker := clientsKey(current.TenantId), managedClientsKey(current.TenantId)
				switch change {
				case "changed client":
					changed := *current
					changed.Status = "DISABLED"
					raw, _ := json.Marshal(changed)
					if err := redisClient.HSet(ctx, key, current.Id, raw).Err(); err != nil {
						t.Fatal(err)
					}
				case "deleted client":
					if err := redisClient.HDel(ctx, key, current.Id).Err(); err != nil {
						t.Fatal(err)
					}
				case "changed owner marker":
					if err := redisClient.HSet(ctx, marker, current.Id, "changed").Err(); err != nil {
						t.Fatal(err)
					}
				}
				before, err := redisClient.HGetAll(ctx, key).Result()
				if err != nil {
					t.Fatal(err)
				}
				want := []string{"code-admin:logs:platform:read", "code-admin:logs:read"}
				reconciler := repo.(ExistingAudienceScopeReconciler)
				stored, err := reconciler.ReconcileCodeAdminAudienceScopes(ctx, current.TenantId, current, want)
				if change != "none" {
					after, _ := redisClient.HGetAll(ctx, key).Result()
					if !errors.Is(err, domain.ErrManagedClientConflict) || stored != nil || !reflect.DeepEqual(before, after) {
						t.Fatal("stale client or owner was overwritten or recreated")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := reconciler.ReconcileCodeAdminAudienceScopes(ctx, current.TenantId, stored, want); err != nil {
					t.Fatalf("idempotent ceiling update: %v", err)
				}
				reloaded, err := repo.Get(ctx, current.TenantId, current.Id)
				expected := *current
				expected.DefaultScopes = want
				if err != nil || !reflect.DeepEqual(reloaded, &expected) {
					t.Fatal("ceiling update changed the client identity or owner")
				}
			})
		}
	}
}
