package saml

import (
	"context"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
)

func newTestJIT(t *testing.T) (*JITProvisioner, *prometheus.Registry) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	t.Cleanup(func() {
		_ = rdb.Close()
		mr.Close()
	})
	return NewJITProvisioner(rdb, m), reg
}

// TestJIT_Create_Once verifies that the first jitUpsert call creates the user.
func TestJIT_Create_Once(t *testing.T) {
	j, reg := newTestJIT(t)
	ctx := context.Background()

	rec := IdPRecord{TenantID: "t-001"}
	va := &VerifiedAssertion{
		NameID: "user@example.com",
		Attributes: map[string][]string{
			"email": {"user@example.com"},
			"name":  {"Alice"},
			"roles": {"ADMIN"},
		},
	}

	created, u, err := j.jitUpsert(ctx, rec, va)
	if err != nil {
		t.Fatalf("jitUpsert: %v", err)
	}
	if !created {
		t.Fatal("expected created=true")
	}
	if u.ID == "" {
		t.Fatal("expected non-empty user ID")
	}
	if u.Email != "user@example.com" {
		t.Fatalf("email = %q, want %q", u.Email, "user@example.com")
	}
	if u.Name != "Alice" {
		t.Fatalf("name = %q, want %q", u.Name, "Alice")
	}
	if u.Role != "ADMIN" {
		t.Fatalf("role = %q, want %q", u.Role, "ADMIN")
	}
	if u.ExternalSubject != "user@example.com" {
		t.Fatalf("externalSubject = %q, want %q", u.ExternalSubject, "user@example.com")
	}
	if u.CreatedAt.IsZero() {
		t.Fatal("expected non-zero CreatedAt")
	}

	// Verify tikti_saml_jit_provisions_total metric was emitted.
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var found bool
	for _, f := range fams {
		if f.GetName() == "tikti_saml_jit_provisions_total" {
			found = true
			metrics := f.GetMetric()
			if len(metrics) != 1 {
				t.Fatalf("expected 1 metric series, got %d", len(metrics))
			}
			if v := metrics[0].GetCounter().GetValue(); v != 1 {
				t.Fatalf("expected counter=1, got %f", v)
			}
		}
	}
	if !found {
		t.Fatal("tikti_saml_jit_provisions_total metric not found")
	}
}

// TestJIT_Update_Subsequent verifies that the second call updates the user
// (created=false) while preserving the original ID and CreatedAt.
func TestJIT_Update_Subsequent(t *testing.T) {
	j, _ := newTestJIT(t)
	ctx := context.Background()

	rec := IdPRecord{TenantID: "t-001"}
	va1 := &VerifiedAssertion{
		NameID: "user@example.com",
		Attributes: map[string][]string{
			"email": {"user@example.com"},
			"name":  {"Alice"},
			"roles": {"ADMIN"},
		},
	}

	created1, u1, err := j.jitUpsert(ctx, rec, va1)
	if err != nil {
		t.Fatalf("first jitUpsert: %v", err)
	}
	if !created1 {
		t.Fatal("expected first call to create")
	}

	va2 := &VerifiedAssertion{
		NameID: "user@example.com",
		Attributes: map[string][]string{
			"email": {"alice-new@example.com"},
			"name":  {"Alice New"},
			"roles": {"COMPANY_ADMIN"},
		},
	}

	created2, u2, err := j.jitUpsert(ctx, rec, va2)
	if err != nil {
		t.Fatalf("second jitUpsert: %v", err)
	}
	if created2 {
		t.Fatal("expected second call to update, not create")
	}
	if u2.ID != u1.ID {
		t.Fatalf("ID changed: %q → %q", u1.ID, u2.ID)
	}
	if u2.Email != "alice-new@example.com" {
		t.Fatalf("email = %q, want %q", u2.Email, "alice-new@example.com")
	}
	if u2.Name != "Alice New" {
		t.Fatalf("name = %q, want %q", u2.Name, "Alice New")
	}
	if u2.Role != "COMPANY_ADMIN" {
		t.Fatalf("role = %q, want %q", u2.Role, "COMPANY_ADMIN")
	}
	if !u2.CreatedAt.Equal(u1.CreatedAt) {
		t.Fatalf("CreatedAt changed: %v → %v", u1.CreatedAt, u2.CreatedAt)
	}
}

// TestJIT_Race_100Concurrent verifies that among 100 concurrent callers with
// the same NameID, exactly 1 observes created=true, all share the same user
// ID, and only 1 record exists in Redis.
func TestJIT_Race_100Concurrent(t *testing.T) {
	j, _ := newTestJIT(t)
	ctx := context.Background()

	rec := IdPRecord{TenantID: "t-001"}
	va := &VerifiedAssertion{
		NameID: "race@example.com",
		Attributes: map[string][]string{
			"email": {"race@example.com"},
			"name":  {"Racer"},
			"roles": {"ADMIN"},
		},
	}

	const goroutines = 100
	type res struct {
		created bool
		user    User
		err     error
	}
	results := make(chan res, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			created, u, err := j.jitUpsert(ctx, rec, va)
			results <- res{created, u, err}
		}()
	}

	wg.Wait()
	close(results)

	var creators int
	ids := make(map[string]int)
	for r := range results {
		if r.err != nil {
			t.Fatalf("jitUpsert error: %v", r.err)
		}
		if r.created {
			creators++
		}
		ids[r.user.ID]++
	}

	if creators != 1 {
		t.Fatalf("expected exactly 1 creator, got %d", creators)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 unique user ID, got %d: %v", len(ids), ids)
	}

	// Verify exactly 1 record in Redis for this NameID.
	keys, err := j.rdb.Keys(ctx, jitKeyPrefix+"*").Result()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 JIT key in Redis, got %d", len(keys))
	}
}
