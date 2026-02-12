package providers

import (
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

func TestBuildRedisOptions_NilConfig(t *testing.T) {
	if _, err := buildRedisOptions(nil); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBuildRedisOptions_InvalidRedisURL(t *testing.T) {
	t.Setenv("REDIS_URL", "://bad")
	cfg := &config.Config{}
	if _, err := buildRedisOptions(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBuildRedisOptions_UsesRedisURLAndFallbacks(t *testing.T) {
	t.Setenv("REDIS_URL", "redis://localhost:6380/0")
	t.Setenv("REDIS_PASSWORD", "env-pass")
	cfg := &config.Config{RedisDB: 2}
	opts, err := buildRedisOptions(cfg)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if opts.Addr != "localhost:6380" {
		t.Fatalf("unexpected addr: %s", opts.Addr)
	}
	if opts.Password != "env-pass" {
		t.Fatalf("unexpected password: %s", opts.Password)
	}
	if opts.DB != 2 {
		t.Fatalf("unexpected db: %d", opts.DB)
	}
}

func TestBuildRedisOptions_HostPortBranches(t *testing.T) {
	cfg := &config.Config{
		RedisAddr: "cache:6500",
		RedisPort: 7001,
		RedisDB:   1,
	}
	opts, err := buildRedisOptions(cfg)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if opts.Addr != "cache:6500" {
		t.Fatalf("unexpected addr: %s", opts.Addr)
	}
	if opts.DB != 1 {
		t.Fatalf("unexpected db: %d", opts.DB)
	}
}

func TestBuildRedisOptions_InvalidEnvPortOrDB(t *testing.T) {
	t.Setenv("REDIS_HOST", "localhost")
	t.Setenv("REDIS_PORT", "bad")
	cfg := &config.Config{}
	if _, err := buildRedisOptions(cfg); err == nil {
		t.Fatalf("expected error for invalid REDIS_PORT")
	}

	t.Setenv("REDIS_PORT", "6379")
	t.Setenv("REDIS_DB", "bad")
	if _, err := buildRedisOptions(cfg); err == nil {
		t.Fatalf("expected error for invalid REDIS_DB")
	}
}

func TestBuildRedisOptions_DBBelowZeroIsNormalized(t *testing.T) {
	cfg := &config.Config{RedisHost: "localhost", RedisPort: 6379, RedisDB: -10}
	opts, err := buildRedisOptions(cfg)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if opts.DB != 0 {
		t.Fatalf("expected db=0, got %d", opts.DB)
	}
}

func TestNewRedisProvider_PingFailure(t *testing.T) {
	cfg := &config.Config{
		RedisHost: "127.0.0.1",
		RedisPort: 1,
		RedisDB:   0,
	}
	if _, err := NewRedisProvider(cfg); err == nil {
		t.Fatalf("expected ping error")
	}
}

func TestNewRedisProvider_SuccessWithMiniRedis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer mr.Close()

	cfg := &config.Config{
		RedisAddr: mr.Addr(),
		RedisDB:   0,
	}
	client, err := NewRedisProvider(cfg)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if client == nil {
		t.Fatalf("expected client")
	}
}

func TestCleanPlaceholder(t *testing.T) {
	if got := cleanPlaceholder("${A}"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
	if got := cleanPlaceholder("  x  "); got != "x" {
		t.Fatalf("expected x, got %q", got)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "a", "b"); got != "a" {
		t.Fatalf("unexpected: %s", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Fatalf("unexpected: %s", got)
	}
}

func TestHostPortFromAddr(t *testing.T) {
	host, port := hostPortFromAddr("")
	if host != "" || port != 0 {
		t.Fatalf("unexpected empty parse")
	}
	host, port = hostPortFromAddr("cache")
	if host != "cache" || port != 0 {
		t.Fatalf("unexpected parse: %s %d", host, port)
	}
	host, port = hostPortFromAddr("cache:6379")
	if host != "cache" || port != 6379 {
		t.Fatalf("unexpected parse: %s %d", host, port)
	}
	host, port = hostPortFromAddr("cache:abc")
	if host != "cache" || port != 0 {
		t.Fatalf("unexpected parse: %s %d", host, port)
	}
}
