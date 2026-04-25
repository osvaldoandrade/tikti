package migrations

import (
	"context"
	"encoding/json"

	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	usersHash    = "users_v2"
	scanCount    = 500
)

// Counter records the number of user records processed during migration 0007.
var Counter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "tikti_migration_0007_records_total",
		Help: "Number of user records processed by migration 0007.",
	},
	[]string{"result"},
)

// Run iterates all user records in the users_v2 hash with HSCAN COUNT 500,
// sets authSource=password and externalSubject="" on records where those
// fields are absent, and emits Prometheus counters per 1000 records.
func Run(ctx context.Context, rdb redis.Cmdable, m *prometheus.CounterVec) error {
	var cursor uint64

	for {
		keys, nextCursor, err := rdb.HScan(ctx, usersHash, cursor, "*", scanCount).Result()
		if err != nil {
			return err
		}

		// HScan returns alternating field/value pairs.
		for i := 0; i+1 < len(keys); i += 2 {
			userID := keys[i]
			raw := keys[i+1]

			var u domain.User
			if err := json.Unmarshal([]byte(raw), &u); err != nil {
				m.WithLabelValues("error").Inc()
				continue
			}

			if u.AuthSource != "" {
				m.WithLabelValues("skipped").Inc()
				continue
			}

			u.AuthSource = domain.AuthSourcePassword
			// externalSubject stays "" (its zero value)

			data, err := json.Marshal(&u)
			if err != nil {
				m.WithLabelValues("error").Inc()
				continue
			}

			if err := rdb.HSet(ctx, usersHash, userID, data).Err(); err != nil {
				m.WithLabelValues("error").Inc()
				continue
			}

			m.WithLabelValues("updated").Inc()
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

// Down removes the authSource and externalSubject fields from all user records,
// restoring them to their pre-migration state. This is the manual rollback
// procedure and is never executed automatically.
func Down(ctx context.Context, rdb redis.Cmdable) error {
	var cursor uint64

	for {
		keys, nextCursor, err := rdb.HScan(ctx, usersHash, cursor, "*", scanCount).Result()
		if err != nil {
			return err
		}

		for i := 0; i+1 < len(keys); i += 2 {
			userID := keys[i]
			raw := keys[i+1]

			var fields map[string]interface{}
			if err := json.Unmarshal([]byte(raw), &fields); err != nil {
				continue
			}

			delete(fields, "authSource")
			delete(fields, "externalSubject")

			data, err := json.Marshal(fields)
			if err != nil {
				continue
			}

			_ = rdb.HSet(ctx, usersHash, userID, data).Err()
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}
