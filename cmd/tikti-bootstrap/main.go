package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/repository"
)

func main() {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("TIKTI_BOOTSTRAP_LOCAL_ONLY")), "true") {
		fmt.Fprintln(os.Stderr, "refusing bootstrap without TIKTI_BOOTSTRAP_LOCAL_ONLY=true")
		os.Exit(1)
	}
	redisAddress := required("REDIS_ADDR")
	cfg := settings{
		tenantID: required("TIKTI_BOOTSTRAP_TENANT_ID"), tenantName: required("TIKTI_BOOTSTRAP_TENANT_NAME"),
		email: required("TIKTI_BOOTSTRAP_EMAIL"), password: required("TIKTI_BOOTSTRAP_PASSWORD"),
		audience: required("TIKTI_BOOTSTRAP_AUDIENCE"), scopes: splitScopes(required("TIKTI_BOOTSTRAP_SCOPES")),
		workloadSubject: strings.TrimSpace(os.Getenv("TIKTI_BOOTSTRAP_WORKLOAD_SUBJECT")),
	}
	if redisAddress == "" || cfg.tenantID == "" || cfg.tenantName == "" || cfg.email == "" || cfg.password == "" || cfg.audience == "" || len(cfg.scopes) == 0 {
		os.Exit(1)
	}
	client := redis.NewClient(&redis.Options{Addr: redisAddress, Password: os.Getenv("REDIS_PASSWORD")})
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Tikti bootstrap could not reach Redis")
		os.Exit(1)
	}
	err := bootstrap(ctx, stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Tikti bootstrap failed:", err)
		os.Exit(1)
	}
	fmt.Println("Tikti local bootstrap is ready for tenant", cfg.tenantID)
}

func required(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		fmt.Fprintln(os.Stderr, name, "is required")
	}
	return value
}

func splitScopes(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}
