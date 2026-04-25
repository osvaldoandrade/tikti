package main

import (
	"context"
	"testing"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

func TestRemoveIdP_Success(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	// Pre-register an IdP.
	_ = store.PutIdP(ctx, saml.IdPRecord{
		TenantID: "t-remove",
		EntityID: "https://idp.example.com",
	})

	if err := removeIdP(ctx, store, "t-remove"); err != nil {
		t.Fatalf("removeIdP: %v", err)
	}

	// Verify the record is gone.
	_, err := store.GetIdP(ctx, "t-remove")
	if err != saml.ErrIdPNotFound {
		t.Errorf("expected ErrIdPNotFound after remove, got %v", err)
	}
}

func TestRemoveIdP_NotFound(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	err := removeIdP(ctx, store, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant, got nil")
	}
}

func TestRemoveIdP_EmptyTID(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	err := removeIdP(ctx, store, "")
	if err == nil {
		t.Fatal("expected error for empty tid, got nil")
	}
}

func TestConfirmRemove_YesFlag(t *testing.T) {
	if !confirmRemove("t-001", true) {
		t.Error("confirmRemove with skipConfirm=true should return true")
	}
}

func TestRemoveIdP_OtherTenantsUnaffected(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	// Register two tenants.
	_ = store.PutIdP(ctx, saml.IdPRecord{TenantID: "t-keep", EntityID: "https://keep.example.com"})
	_ = store.PutIdP(ctx, saml.IdPRecord{TenantID: "t-remove", EntityID: "https://remove.example.com"})

	if err := removeIdP(ctx, store, "t-remove"); err != nil {
		t.Fatalf("removeIdP: %v", err)
	}

	// Removed tenant should be gone.
	_, err := store.GetIdP(ctx, "t-remove")
	if err != saml.ErrIdPNotFound {
		t.Errorf("expected ErrIdPNotFound for removed tenant, got %v", err)
	}

	// Other tenant should be untouched.
	kept, err := store.GetIdP(ctx, "t-keep")
	if err != nil {
		t.Fatalf("GetIdP for kept tenant: %v", err)
	}
	if kept.EntityID != "https://keep.example.com" {
		t.Errorf("kept tenant EntityID = %q, want %q", kept.EntityID, "https://keep.example.com")
	}
}
