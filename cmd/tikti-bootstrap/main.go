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
	if !booleanEnvironment("TIKTI_BOOTSTRAP_ACKNOWLEDGE_IDEMPOTENT") &&
		!booleanEnvironment("TIKTI_BOOTSTRAP_LOCAL_ONLY") {
		fmt.Fprintln(os.Stderr, "refusing bootstrap without TIKTI_BOOTSTRAP_ACKNOWLEDGE_IDEMPOTENT=true")
		os.Exit(1)
	}
	redisAddress := required("REDIS_ADDR")
	password, err := optionalSecretFile("TIKTI_BOOTSTRAP_PASSWORD_FILE", "TIKTI_BOOTSTRAP_PASSWORD")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TIKTI_BOOTSTRAP_PASSWORD_FILE:", err)
		os.Exit(1)
	}
	passwordHash, err := optionalSecretFile("TIKTI_BOOTSTRAP_PASSWORD_HASH_FILE", "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TIKTI_BOOTSTRAP_PASSWORD_HASH_FILE:", err)
		os.Exit(1)
	}
	redisPassword, err := optionalSecretFile("REDIS_PASSWORD_FILE", "REDIS_PASSWORD")
	if err != nil {
		fmt.Fprintln(os.Stderr, "REDIS_PASSWORD_FILE:", err)
		os.Exit(1)
	}
	cfg := settings{
		tenantID: required("TIKTI_BOOTSTRAP_TENANT_ID"), tenantName: required("TIKTI_BOOTSTRAP_TENANT_NAME"),
		email: required("TIKTI_BOOTSTRAP_EMAIL"), password: password, passwordHash: passwordHash,
		audience: required("TIKTI_BOOTSTRAP_AUDIENCE"), scopes: splitScopes(required("TIKTI_BOOTSTRAP_SCOPES")),
		workloadSubject: strings.TrimSpace(os.Getenv("TIKTI_BOOTSTRAP_WORKLOAD_SUBJECT")),
	}
	if redisAddress == "" || cfg.tenantID == "" || cfg.tenantName == "" || cfg.email == "" ||
		(cfg.password == "" && cfg.passwordHash == "") || cfg.audience == "" || len(cfg.scopes) == 0 {
		os.Exit(1)
	}
	client := redis.NewClient(&redis.Options{Addr: redisAddress, Password: redisPassword})
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Tikti bootstrap could not reach Redis")
		os.Exit(1)
	}
	err = bootstrap(ctx, stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Tikti bootstrap failed:", err)
		os.Exit(1)
	}
	fmt.Println("Tikti bootstrap is ready for tenant", cfg.tenantID)
}

func booleanEnvironment(name string) bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(name)), "true")
}

func optionalSecretFile(fileEnvironment string, valueEnvironment string) (string, error) {
	path := strings.TrimSpace(os.Getenv(fileEnvironment))
	direct := ""
	if valueEnvironment != "" {
		direct = strings.TrimSpace(os.Getenv(valueEnvironment))
	}
	if path != "" && direct != "" {
		return "", fmt.Errorf("configure either %s or %s", fileEnvironment, valueEnvironment)
	}
	if path == "" {
		return direct, nil
	}
	// #nosec G304 G703 -- the path is supplied by the trusted bootstrap Job
	// and must resolve to one bounded regular Secret Manager CSI file.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4<<10 {
		return "", fmt.Errorf("secret file must be a regular file between 1 and 4096 bytes")
	}
	// #nosec G304 G703 -- see the bounded regular-file validation above.
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("secret file is empty")
	}
	return value, nil
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
