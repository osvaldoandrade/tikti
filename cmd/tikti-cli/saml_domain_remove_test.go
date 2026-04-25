package main

import (
	"context"
	"testing"
)

// TestDomainRemove_Success verifies that removing a mapped domain works.
func TestDomainRemove_Success(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	// Add a domain mapping first.
	if err := domainAdd(ctx, store, "acme.com", "t-acme"); err != nil {
		t.Fatalf("domainAdd: %v", err)
	}

	// Remove it.
	if err := domainRemove(ctx, store, "acme.com"); err != nil {
		t.Fatalf("domainRemove: %v", err)
	}

	// Verify gone.
	_, err := store.GetDomain(ctx, "acme.com")
	if err == nil {
		t.Error("expected error after remove, got nil")
	}
}

// TestDomainRemove_NonExistent verifies that removing a non-existent domain
// does not return an error (idempotent delete).
func TestDomainRemove_NonExistent(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	if err := domainRemove(ctx, store, "nosuch.com"); err != nil {
		t.Fatalf("domainRemove on non-existent: %v", err)
	}
}
