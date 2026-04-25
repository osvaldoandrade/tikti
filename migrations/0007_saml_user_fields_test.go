package migrations

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// counterValue extracts the current total for a label from a CounterVec.
func counterValue(cv *prometheus.CounterVec, label string) float64 {
	c, err := cv.GetMetricWithLabelValues(label)
	if err != nil {
		return 0
	}
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// seedUsers inserts n users into the users_v2 hash. If withAuth is true the
// user already carries authSource; otherwise the field is left at Go zero.
func seedUsers(ctx context.Context, t *testing.T, rdb *redis.Client, n int, withAuth bool) {
	t.Helper()
	for i := 0; i < n; i++ {
		u := domain.User{
			Id:    fmt.Sprintf("uid-%d", i),
			Email: fmt.Sprintf("u%d@test.com", i),
		}
		if withAuth {
			u.AuthSource = domain.AuthSourcePassword
		}
		data, err := json.Marshal(&u)
		if err != nil {
			t.Fatalf("marshal user %d: %v", i, err)
		}
		if err := rdb.HSet(ctx, usersHash, u.Id, data).Err(); err != nil {
			t.Fatalf("hset user %d: %v", i, err)
		}
	}
}

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func newCounter() *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_migration_0007_records_total",
		Help: "test counter",
	}, []string{"result"})
}

func TestMigration_Idempotent(t *testing.T) {
	rdb := newTestRedis(t)
	ctx := context.Background()
	seedUsers(ctx, t, rdb, 100, false)

	m := newCounter()
	if err := Run(ctx, rdb, m); err != nil {
		t.Fatalf("first run: %v", err)
	}

	updated1 := counterValue(m, "updated")
	if updated1 != 100 {
		t.Fatalf("first run: expected 100 updated, got %v", updated1)
	}

	// Second run should produce zero changes.
	m2 := newCounter()
	if err := Run(ctx, rdb, m2); err != nil {
		t.Fatalf("second run: %v", err)
	}

	updated2 := counterValue(m2, "updated")
	if updated2 != 0 {
		t.Fatalf("second run: expected 0 updated, got %v", updated2)
	}

	skipped2 := counterValue(m2, "skipped")
	if skipped2 != 100 {
		t.Fatalf("second run: expected 100 skipped, got %v", skipped2)
	}
}

func TestMigration_OnlyFillsMissing(t *testing.T) {
	rdb := newTestRedis(t)
	ctx := context.Background()

	// Insert a SAML user that already has authSource set.
	samlUser := domain.User{
		Id:              "saml-1",
		Email:           "saml@test.com",
		AuthSource:      domain.AuthSourceSAML,
		ExternalSubject: "ext-sub-123",
	}
	data, _ := json.Marshal(&samlUser)
	if err := rdb.HSet(ctx, usersHash, samlUser.Id, data).Err(); err != nil {
		t.Fatalf("seed saml user: %v", err)
	}

	// Insert a password user without authSource.
	pwUser := domain.User{
		Id:    "pw-1",
		Email: "pw@test.com",
	}
	data, _ = json.Marshal(&pwUser)
	if err := rdb.HSet(ctx, usersHash, pwUser.Id, data).Err(); err != nil {
		t.Fatalf("seed pw user: %v", err)
	}

	m := newCounter()
	if err := Run(ctx, rdb, m); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Verify the SAML user is untouched.
	raw, err := rdb.HGet(ctx, usersHash, "saml-1").Result()
	if err != nil {
		t.Fatalf("hget saml-1: %v", err)
	}
	var after domain.User
	if err := json.Unmarshal([]byte(raw), &after); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if after.AuthSource != domain.AuthSourceSAML {
		t.Fatalf("expected saml, got %s", after.AuthSource)
	}
	if after.ExternalSubject != "ext-sub-123" {
		t.Fatalf("expected ext-sub-123, got %s", after.ExternalSubject)
	}

	// Verify the password user was updated.
	raw, err = rdb.HGet(ctx, usersHash, "pw-1").Result()
	if err != nil {
		t.Fatalf("hget pw-1: %v", err)
	}
	if err := json.Unmarshal([]byte(raw), &after); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if after.AuthSource != domain.AuthSourcePassword {
		t.Fatalf("expected password, got %s", after.AuthSource)
	}

	if counterValue(m, "updated") != 1 {
		t.Fatalf("expected 1 updated, got %v", counterValue(m, "updated"))
	}
	if counterValue(m, "skipped") != 1 {
		t.Fatalf("expected 1 skipped, got %v", counterValue(m, "skipped"))
	}
}

func TestMigration_EmitsCounter(t *testing.T) {
	rdb := newTestRedis(t)
	ctx := context.Background()
	const total = 250
	seedUsers(ctx, t, rdb, total, false)

	m := newCounter()
	if err := Run(ctx, rdb, m); err != nil {
		t.Fatalf("run: %v", err)
	}

	updated := counterValue(m, "updated")
	skipped := counterValue(m, "skipped")
	errors := counterValue(m, "error")

	if updated+skipped+errors != total {
		t.Fatalf("counter sum: expected %d, got %v", total, updated+skipped+errors)
	}
	if updated != total {
		t.Fatalf("expected %d updated, got %v", total, updated)
	}
}
