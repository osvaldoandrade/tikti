package main

import (
	"context"
	"errors"
	"testing"
)

// TestDomainAdd_Success verifies that a new domain mapping is created.
func TestDomainAdd_Success(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	if err := domainAdd(ctx, store, "acme.com", "t-acme"); err != nil {
		t.Fatalf("domainAdd: %v", err)
	}

	tid, err := store.GetDomain(ctx, "acme.com")
	if err != nil {
		t.Fatalf("GetDomain after add: %v", err)
	}
	if tid != "t-acme" {
		t.Errorf("GetDomain = %q, want %q", tid, "t-acme")
	}
}

// TestDomainAdd_Idempotent verifies that adding the same domain→tid pair
// again succeeds silently (idempotent).
func TestDomainAdd_Idempotent(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	if err := domainAdd(ctx, store, "acme.com", "t-acme"); err != nil {
		t.Fatalf("first domainAdd: %v", err)
	}
	if err := domainAdd(ctx, store, "acme.com", "t-acme"); err != nil {
		t.Fatalf("second domainAdd (idempotent): %v", err)
	}
}

// TestDomainAdd_Conflict verifies that mapping a domain already owned by a
// different tenant returns a cliError with exit code 1.
func TestDomainAdd_Conflict(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	// Pre-register domain for tenant t-acme.
	if err := domainAdd(ctx, store, "acme.com", "t-acme"); err != nil {
		t.Fatalf("initial domainAdd: %v", err)
	}

	// Attempt to map the same domain to a different tenant.
	err := domainAdd(ctx, store, "acme.com", "t-other")
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}

	var ce *cliError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *cliError, got %T: %v", err, err)
	}
	if ce.exit != 1 {
		t.Errorf("exit = %d, want 1", ce.exit)
	}
}

// TestDomainAdd_NormalizesDomain verifies that domains are lowercased.
func TestDomainAdd_NormalizesDomain(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	if err := domainAdd(ctx, store, "ACME.COM", "t-acme"); err != nil {
		t.Fatalf("domainAdd: %v", err)
	}

	tid, err := store.GetDomain(ctx, "acme.com")
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if tid != "t-acme" {
		t.Errorf("GetDomain = %q, want %q", tid, "t-acme")
	}
}
