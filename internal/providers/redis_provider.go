package providers

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

const (
	defaultRedisHost = "localhost"
	defaultRedisPort = 6379
)

// NewRedisProvider builds a Redis client configured for the configured host/port/db/password.
func NewRedisProvider(cfg *config.Config) (*redis.Client, error) {
	opts, err := buildRedisOptions(cfg)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}
	return client, nil
}

func buildRedisOptions(cfg *config.Config) (*redis.Options, error) {
	if cfg == nil {
		return nil, fmt.Errorf("redis config is nil")
	}

	if url := firstNonEmpty(strings.TrimSpace(os.Getenv("REDIS_URL")), cleanPlaceholder(cfg.RedisURL)); url != "" {
		opts, err := redis.ParseURL(url)
		if err != nil {
			return nil, fmt.Errorf("invalid REDIS_URL: %w", err)
		}
		if opts.Password == "" {
			opts.Password = firstNonEmpty(strings.TrimSpace(os.Getenv("REDIS_PASSWORD")), cleanPlaceholder(cfg.RedisPassword))
		}
		if opts.DB == 0 && cfg.RedisDB > 0 {
			opts.DB = cfg.RedisDB
		}
		return opts, nil
	}

	host := firstNonEmpty(strings.TrimSpace(os.Getenv("REDIS_HOST")), cleanPlaceholder(cfg.RedisHost))
	if host == "" {
		if addrHost, _ := hostPortFromAddr(cleanPlaceholder(cfg.RedisAddr)); addrHost != "" {
			host = addrHost
		}
	}
	if host == "" {
		host = defaultRedisHost
	}

	port := cfg.RedisPort
	if envPort := strings.TrimSpace(os.Getenv("REDIS_PORT")); envPort != "" {
		parsed, err := strconv.Atoi(envPort)
		if err != nil {
			return nil, fmt.Errorf("invalid REDIS_PORT: %w", err)
		}
		port = parsed
	}
	if port == 0 {
		if _, addrPort := hostPortFromAddr(cleanPlaceholder(cfg.RedisAddr)); addrPort != 0 {
			port = addrPort
		}
	}
	if port == 0 {
		port = defaultRedisPort
	}

	db := cfg.RedisDB
	if envDB := strings.TrimSpace(os.Getenv("REDIS_DB")); envDB != "" {
		parsed, err := strconv.Atoi(envDB)
		if err != nil {
			return nil, fmt.Errorf("invalid REDIS_DB: %w", err)
		}
		db = parsed
	}
	if db < 0 {
		db = 0
	}

	password := firstNonEmpty(strings.TrimSpace(os.Getenv("REDIS_PASSWORD")), cleanPlaceholder(cfg.RedisPassword))

	return &redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		DB:       db,
		Password: password,
	}, nil
}

func cleanPlaceholder(val string) string {
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, "${") && strings.HasSuffix(val, "}") {
		return ""
	}
	return val
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func hostPortFromAddr(addr string) (string, int) {
	if addr == "" {
		return "", 0
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	parsed, err := strconv.Atoi(port)
	if err != nil {
		return host, 0
	}
	return host, parsed
}
