package main

import (
	"context"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

func TestShowIdP_Success(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	now := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	_ = store.PutIdP(ctx, saml.IdPRecord{
		TenantID:     "t-show",
		EntityID:     "https://idp.example.com",
		SSOURL:       "https://idp.example.com/sso",
		SLOURL:       "https://idp.example.com/slo",
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		SigningCerts: [][]byte{[]byte("cert1")},
		MetadataURL:  "https://idp.example.com/metadata",
		LastFetched:  now,
	})

	result, err := showIdP(ctx, store, "t-show")
	if err != nil {
		t.Fatalf("showIdP: %v", err)
	}

	// Verify stable JSON shape.
	expectedKeys := []string{
		"tenant_id", "entity_id", "sso_url", "slo_url",
		"name_id_format", "num_signing_certs", "num_encryption_certs",
		"attribute_map", "metadata_url", "last_fetched",
	}
	for _, key := range expectedKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("missing key %q in show output", key)
		}
	}

	if result["tenant_id"] != "t-show" {
		t.Errorf("tenant_id = %q, want %q", result["tenant_id"], "t-show")
	}
	if result["entity_id"] != "https://idp.example.com" {
		t.Errorf("entity_id = %q, want %q", result["entity_id"], "https://idp.example.com")
	}
	if result["num_signing_certs"] != 1 {
		t.Errorf("num_signing_certs = %v, want 1", result["num_signing_certs"])
	}
	if result["metadata_url"] != "https://idp.example.com/metadata" {
		t.Errorf("metadata_url = %q, want %q", result["metadata_url"], "https://idp.example.com/metadata")
	}
	if result["last_fetched"] != "2025-06-15T10:00:00Z" {
		t.Errorf("last_fetched = %q, want %q", result["last_fetched"], "2025-06-15T10:00:00Z")
	}
}

func TestShowIdP_NotFound(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	_, err := showIdP(ctx, store, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant, got nil")
	}
}

func TestShowIdP_EmptyTID(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	_, err := showIdP(ctx, store, "")
	if err == nil {
		t.Fatal("expected error for empty TID, got nil")
	}
}
