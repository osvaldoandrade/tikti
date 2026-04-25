package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/vmihailenco/msgpack/v5"

	rkeys "github.com/osvaldoandrade/tikti/internal/redis"
)

// newTestRedis spins up a miniredis instance and returns a connected client.
func newTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = rdb.Close()
		mr.Close()
	})
	return rdb, mr
}

// testCertPEM generates a fresh self-signed certificate PEM for testing.
func testCertPEM(t *testing.T) (keyPEM, certPEM []byte) {
	t.Helper()
	k, c, err := generateSelfSignedKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return k, c
}

// TestRotate_Prepare_PublishesBoth verifies that --prepare produces metadata
// containing 2 signing certificates (old + new).
func TestRotate_Prepare_PublishesBoth(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := context.Background()

	// Generate an "old" key pair to use as the current SP cert.
	_, oldCertPEM := testCertPEM(t)

	// Write old cert to a temp file.
	oldCertPath := t.TempDir() + "/sp.crt"
	oldKeyPath := t.TempDir() + "/sp.key"

	// We only need the cert file for --prepare; the key file isn't read
	// (the new key is generated internally).  Write a dummy key.
	if err := writeTestFile(oldKeyPath, []byte("unused")); err != nil {
		t.Fatal(err)
	}
	if err := writeTestFile(oldCertPath, oldCertPEM); err != nil {
		t.Fatal(err)
	}

	// Run prepare — output to a temp file.
	outFile := t.TempDir() + "/metadata.xml"
	err := rotatePrepare(
		ctx, rdb,
		oldKeyPath, oldCertPath,
		"https://sp.example.com/saml",
		"https://sp.example.com/saml/acs",
		"https://sp.example.com/saml/slo",
		outFile,
		2048,
		false,
	)
	if err != nil {
		t.Fatalf("rotatePrepare: %v", err)
	}

	// Verify metadata contains 2 signing KeyDescriptor elements.
	meta, err := readTestFile(outFile)
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	count := strings.Count(string(meta), `use="signing"`)
	if count != 2 {
		t.Errorf("expected 2 signing KeyDescriptors, got %d", count)
	}

	// Verify rotation state exists in Redis.
	exists, err := rdb.Exists(ctx, rkeys.SAMLSPRotationKey).Result()
	if err != nil {
		t.Fatalf("redis exists: %v", err)
	}
	if exists != 1 {
		t.Error("rotation state not found in Redis after --prepare")
	}
}

// TestRotate_Commit_RemovesOld verifies that --commit produces metadata
// containing only 1 signing certificate (the new one).
func TestRotate_Commit_RemovesOld(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := context.Background()

	// Simulate a prior --prepare by storing rotation state in Redis.
	_, oldCertPEM := testCertPEM(t)
	_, newCertPEM := testCertPEM(t)

	state := rotationState{
		OldCertPEM: oldCertPEM,
		NewCertPEM: newCertPEM,
	}
	data, err := msgpack.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := rdb.Set(ctx, rkeys.SAMLSPRotationKey, data, 0).Err(); err != nil {
		t.Fatalf("set rotation state: %v", err)
	}

	outFile := t.TempDir() + "/metadata.xml"
	err = rotateCommit(
		ctx, rdb,
		"sp.key", "sp.crt",
		"https://sp.example.com/saml",
		"https://sp.example.com/saml/acs",
		"https://sp.example.com/saml/slo",
		outFile,
		false,
	)
	if err != nil {
		t.Fatalf("rotateCommit: %v", err)
	}

	// Verify metadata contains exactly 1 signing KeyDescriptor.
	meta, err := readTestFile(outFile)
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	count := strings.Count(string(meta), `use="signing"`)
	if count != 1 {
		t.Errorf("expected 1 signing KeyDescriptor, got %d", count)
	}

	// Verify rotation state has been removed from Redis.
	exists, err := rdb.Exists(ctx, rkeys.SAMLSPRotationKey).Result()
	if err != nil {
		t.Fatalf("redis exists: %v", err)
	}
	if exists != 0 {
		t.Error("rotation state should be deleted after --commit")
	}
}

// TestRotate_CommitBeforePrepare_Rejected verifies that --commit fails when
// no rotation state exists in Redis.
func TestRotate_CommitBeforePrepare_Rejected(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := context.Background()

	err := rotateCommit(
		ctx, rdb,
		"sp.key", "sp.crt",
		"https://sp.example.com/saml",
		"https://sp.example.com/saml/acs",
		"https://sp.example.com/saml/slo",
		"",
		false,
	)
	if err == nil {
		t.Fatal("expected error when committing without prepare, got nil")
	}

	var ce *cliError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *cliError, got %T: %v", err, err)
	}
	if !strings.Contains(ce.msg, "run --prepare first") {
		t.Errorf("unexpected error message: %s", ce.msg)
	}
}

// --- test helpers ---

func writeTestFile(path string, data []byte) error {
	return writeOutput(path, data)
}

func readTestFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
