package repository

import (
	"context"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestTenantRetirementRetainsIdentityButRevokesAndHidesIt(t *testing.T) {
	client, repo := newTenantRepoForTest(t)
	ctx := context.Background()
	for _, id := range []string{domain.MasterTenantID, "fresh-tenant"} {
		name := "Fresh tenant"
		if id == domain.MasterTenantID {
			name = domain.MasterTenantName
		}
		if err := repo.Create(ctx, &domain.Tenant{Id: id, Slug: id, Name: name, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	retirer, ok := repo.(interface {
		Retire(context.Context, string) error
	})
	if !ok {
		t.Fatal("tenant repository has no safe retirement operation")
	}
	if err := retirer.Retire(ctx, domain.MasterTenantID); err == nil {
		t.Fatal("MASTER retirement allowed")
	}
	for range 2 {
		if err := retirer.Retire(ctx, "fresh-tenant"); err != nil {
			t.Fatal(err)
		}
	}
	if exists := client.HExists(ctx, tenantsHash, "fresh-tenant").Val(); !exists {
		t.Fatal("tenant identity was destroyed rather than retained")
	}
	if tenant, err := repo.Get(ctx, "fresh-tenant"); err != nil || tenant != nil {
		t.Fatalf("retired tenant visible: %v %v", tenant, err)
	}
	if tenants, _, err := repo.List(ctx, 0, 50); err != nil || len(tenants) != 1 || tenants[0].Id != domain.MasterTenantID {
		t.Fatalf("inventory=%v err=%v", tenants, err)
	}
	if _, created, err := repo.CreateIfAbsent(ctx, &domain.Tenant{Id: "fresh-tenant", Slug: "fresh-tenant", Name: "Fresh tenant"}); err == nil || created {
		t.Fatal("retired ID was reusable")
	}
	if err := repo.Create(ctx, &domain.Tenant{Id: "fresh-tenant", Slug: "fresh-tenant", Name: "Fresh tenant"}); err == nil {
		t.Fatal("installation bootstrap could resurrect a retired tenant")
	}
}
