package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/vmihailenco/msgpack/v5"

	rkeys "github.com/osvaldoandrade/tikti/internal/redis"
	"github.com/osvaldoandrade/tikti/internal/saml"
)

// removeIdP is the testable core of "saml idp remove". It verifies the IdP
// record exists and then deletes it.
func removeIdP(ctx context.Context, store saml.Store, tid string) error {
	if tid == "" {
		return errors.New("--tid is required")
	}

	// Verify the IdP record exists before deleting.
	_, err := store.GetIdP(ctx, tid)
	if err != nil {
		return fmt.Errorf("IdP not found for tenant %q: %w", tid, err)
	}

	if err := store.DeleteIdP(ctx, tid); err != nil {
		return fmt.Errorf("deleting IdP: %w", err)
	}
	return nil
}

// flushTenantRequests scans all saml:req:* keys and removes those that
// belong to the given tenant. Requests are short-lived (300 s TTL) so this
// is a best-effort cleanup.
func flushTenantRequests(ctx context.Context, rdb *redis.Client, tid string) (int, error) {
	var (
		cursor  uint64
		deleted int
	)
	pattern := rkeys.SAMLRequestPrefix + "*"
	for {
		keys, next, err := rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return deleted, err
		}
		for _, key := range keys {
			raw, err := rdb.Get(ctx, key).Bytes()
			if err != nil {
				continue // key may have expired
			}
			var rec saml.RequestRecord
			if err := msgpack.Unmarshal(raw, &rec); err != nil {
				continue
			}
			if rec.TenantID == tid {
				if err := rdb.Del(ctx, key).Err(); err == nil {
					deleted++
				}
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return deleted, nil
}

// confirmRemove asks the user for confirmation unless skipConfirm is true.
func confirmRemove(tid string, skipConfirm bool) bool {
	if skipConfirm {
		return true
	}
	fmt.Printf("Remove IdP federation for tenant %q? [y/N]: ", tid)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}
