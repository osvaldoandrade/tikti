package main

import (
	"context"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

func TestListIdPs_Empty(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	records, err := listIdPs(ctx, store)
	if err != nil {
		t.Fatalf("listIdPs: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestListIdPs_Multiple(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	now := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)

	_ = store.PutIdP(ctx, saml.IdPRecord{
		TenantID:    "t-001",
		EntityID:    "https://idp1.example.com",
		LastFetched: now,
	})
	_ = store.PutIdP(ctx, saml.IdPRecord{
		TenantID:    "t-002",
		EntityID:    "https://idp2.example.com",
		LastFetched: now.Add(time.Hour),
	})

	records, err := listIdPs(ctx, store)
	if err != nil {
		t.Fatalf("listIdPs: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	// Verify each record has the expected stable shape.
	for _, r := range records {
		if r["tenant_id"] == nil {
			t.Error("missing tenant_id")
		}
		if r["entity_id"] == nil {
			t.Error("missing entity_id")
		}
		if r["last_fetched"] == nil {
			t.Error("missing last_fetched")
		}
	}
}

func TestListIdPs_JSONShape(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	_ = store.PutIdP(ctx, saml.IdPRecord{
		TenantID:    "t-shape",
		EntityID:    "https://idp.example.com",
		LastFetched: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	records, err := listIdPs(ctx, store)
	if err != nil {
		t.Fatalf("listIdPs: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	r := records[0]
	if r["tenant_id"] != "t-shape" {
		t.Errorf("tenant_id = %q, want %q", r["tenant_id"], "t-shape")
	}
	if r["entity_id"] != "https://idp.example.com" {
		t.Errorf("entity_id = %q, want %q", r["entity_id"], "https://idp.example.com")
	}
	if r["last_fetched"] != "2025-01-01T00:00:00Z" {
		t.Errorf("last_fetched = %q, want %q", r["last_fetched"], "2025-01-01T00:00:00Z")
	}
}

func TestFormatIdPTable(t *testing.T) {
	records := []map[string]any{
		{
			"tenant_id":    "t-001",
			"entity_id":    "https://idp1.example.com",
			"last_fetched": "2025-01-01T00:00:00Z",
		},
	}
	output := formatIdPTable(records)
	if output == "" {
		t.Error("expected non-empty table output")
	}
	// Verify header is present.
	if !containsSubstring(output, "TENANT ID") {
		t.Error("table missing TENANT ID header")
	}
	if !containsSubstring(output, "t-001") {
		t.Error("table missing tenant ID value")
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && searchSubstring(s, sub)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
