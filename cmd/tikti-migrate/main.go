package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	usersHashV2      = "users_v2"
	legacyUsersHash  = "users"
	userByEmailKeyNS = "userByEmail:"
	membershipsNS    = "memberships:"
	membershipsByUsr = "membershipsByUser:"
)

type stats struct {
	total      int
	migrated   int
	skipped    int
	conflicted int
}

func main() {
	var (
		redisAddr     string
		redisPassword string
		redisDB       int
		defaultTenant string
		dryRun        bool
	)

	flag.StringVar(&redisAddr, "redis-addr", "localhost:6379", "Redis host:port")
	flag.StringVar(&redisPassword, "redis-password", "", "Redis password")
	flag.IntVar(&redisDB, "redis-db", 0, "Redis DB")
	flag.StringVar(&defaultTenant, "default-tenant", "default", "Tenant id to attach memberships")
	flag.BoolVar(&dryRun, "dry-run", false, "Scan and report without writing")
	flag.Parse()

	ctx := context.Background()
	client := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       redisDB,
	})
	defer client.Close()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis ping failed: %v", err)
	}

	legacy, err := client.HGetAll(ctx, legacyUsersHash).Result()
	if err != nil {
		log.Fatalf("failed to read legacy users: %v", err)
	}

	st := stats{total: len(legacy)}
	for emailKey, payload := range legacy {
		u, ok := parseUser(emailKey, payload)
		if !ok {
			st.skipped++
			continue
		}

		if u.Email == "" {
			u.Email = emailKey
		}
		if u.Id == "" {
			u.Id = uuid.NewString()
		}
		if u.Role == "" {
			u.Role = domain.RoleCompanyEmployee
		}
		if u.Status == "" {
			u.Status = domain.UserStatusActive
		}
		if u.CreatedAt.IsZero() {
			u.CreatedAt = time.Now().UTC()
		}

		existingID, _ := client.Get(ctx, userByEmailKeyNS+u.Email).Result()
		if existingID != "" && existingID != u.Id {
			st.conflicted++
			log.Printf("conflict: email %s already mapped to %s (legacy %s)", u.Email, existingID, u.Id)
			continue
		}
		if existingID == u.Id {
			st.skipped++
		} else {
			if !dryRun {
				data, _ := json.Marshal(u)
				if err := client.HSet(ctx, usersHashV2, u.Id, data).Err(); err != nil {
					log.Printf("failed to write user %s: %v", u.Email, err)
					continue
				}
				if err := client.Set(ctx, userByEmailKeyNS+u.Email, u.Id, 0).Err(); err != nil {
					log.Printf("failed to index user %s: %v", u.Email, err)
					continue
				}
			}
			st.migrated++
		}

		if !dryRun {
			if err := ensureMembership(ctx, client, defaultTenant, u); err != nil {
				log.Printf("membership error for %s: %v", u.Email, err)
			}
		}
	}

	fmt.Printf("legacy users: %d\n", st.total)
	fmt.Printf("migrated: %d\n", st.migrated)
	fmt.Printf("skipped: %d\n", st.skipped)
	fmt.Printf("conflicts: %d\n", st.conflicted)
	if dryRun {
		fmt.Println("dry-run: no writes performed")
	}
}

func parseUser(emailKey string, payload string) (*domain.User, bool) {
	if strings.TrimSpace(payload) == "" {
		return nil, false
	}
	var u domain.User
	if err := json.Unmarshal([]byte(payload), &u); err != nil {
		log.Printf("failed to parse legacy user %s: %v", emailKey, err)
		return nil, false
	}
	return &u, true
}

func ensureMembership(ctx context.Context, client *redis.Client, tenantID string, u *domain.User) error {
	if tenantID == "" || u == nil || u.Id == "" {
		return nil
	}
	key := membershipsNS + tenantID
	existing, err := client.HGet(ctx, key, u.Id).Result()
	if err == nil && existing != "" {
		return nil
	}
	roles := []string{}
	if u.Role != "" {
		roles = append(roles, string(u.Role))
	}
	m := domain.Membership{
		Id:        uuid.NewString(),
		TenantId:  tenantID,
		UserId:    u.Id,
		Roles:     roles,
		CreatedAt: time.Now().UTC(),
	}
	data, _ := json.Marshal(m)
	if err := client.HSet(ctx, key, u.Id, data).Err(); err != nil {
		return err
	}
	return client.SAdd(ctx, membershipsByUsr+u.Id, tenantID).Err()
}
