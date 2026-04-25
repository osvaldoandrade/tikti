package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

func TestFetchIdPRefresh_Success(t *testing.T) {
	metadataXML, err := os.ReadFile(filepath.Join("..", "..", "internal", "saml", "testdata", "idp_okta.xml"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(metadataXML)
	}))
	defer srv.Close()

	store := newMemStore()
	ctx := context.Background()

	// Pre-register an IdP with a metadata URL.
	oldTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = store.PutIdP(ctx, saml.IdPRecord{
		TenantID:    "t-fetch",
		EntityID:    "https://idp.example.com",
		MetadataURL: srv.URL + "/metadata",
		LastFetched: oldTime,
		AttributeMap: map[string][]string{
			"email": {"mail"},
		},
	})

	opts := fetchIdPOptions{
		TID:        "t-fetch",
		HTTPClient: srv.Client(),
	}

	rec, err := fetchIdPRefresh(ctx, store, opts)
	if err != nil {
		t.Fatalf("fetchIdPRefresh: %v", err)
	}

	// Verify LastFetched was updated.
	if !rec.LastFetched.After(oldTime) {
		t.Errorf("LastFetched not updated: got %v, want after %v", rec.LastFetched, oldTime)
	}

	// Verify tenant ID is preserved.
	if rec.TenantID != "t-fetch" {
		t.Errorf("TenantID = %q, want %q", rec.TenantID, "t-fetch")
	}

	// Verify metadata URL is preserved.
	if rec.MetadataURL != srv.URL+"/metadata" {
		t.Errorf("MetadataURL = %q, want %q", rec.MetadataURL, srv.URL+"/metadata")
	}

	// Verify attribute map is preserved.
	if rec.AttributeMap == nil {
		t.Error("AttributeMap was lost during fetch")
	}

	// Verify record was persisted.
	got, err := store.GetIdP(ctx, "t-fetch")
	if err != nil {
		t.Fatalf("GetIdP after fetch: %v", err)
	}
	if !got.LastFetched.After(oldTime) {
		t.Error("persisted record LastFetched not updated")
	}
}

func TestFetchIdPRefresh_OverrideURL(t *testing.T) {
	metadataXML, err := os.ReadFile(filepath.Join("..", "..", "internal", "saml", "testdata", "idp_okta.xml"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(metadataXML)
	}))
	defer srv.Close()

	store := newMemStore()
	ctx := context.Background()

	// Pre-register an IdP without a metadata URL.
	_ = store.PutIdP(ctx, saml.IdPRecord{
		TenantID: "t-override",
		EntityID: "https://idp.example.com",
	})

	opts := fetchIdPOptions{
		TID:         "t-override",
		MetadataURL: srv.URL + "/metadata",
		HTTPClient:  srv.Client(),
	}

	rec, err := fetchIdPRefresh(ctx, store, opts)
	if err != nil {
		t.Fatalf("fetchIdPRefresh: %v", err)
	}

	if rec.MetadataURL != srv.URL+"/metadata" {
		t.Errorf("MetadataURL = %q, want %q", rec.MetadataURL, srv.URL+"/metadata")
	}
}

func TestFetchIdPRefresh_NotFound(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	opts := fetchIdPOptions{
		TID:        "nonexistent",
		HTTPClient: http.DefaultClient,
	}

	_, err := fetchIdPRefresh(ctx, store, opts)
	if err == nil {
		t.Fatal("expected error for nonexistent tenant, got nil")
	}
}

func TestFetchIdPRefresh_NoURL(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	// Register IdP without metadata URL.
	_ = store.PutIdP(ctx, saml.IdPRecord{
		TenantID: "t-nourl",
		EntityID: "https://idp.example.com",
	})

	opts := fetchIdPOptions{
		TID:        "t-nourl",
		HTTPClient: http.DefaultClient,
	}

	_, err := fetchIdPRefresh(ctx, store, opts)
	if err == nil {
		t.Fatal("expected error when no metadata URL available, got nil")
	}
}

func TestFetchIdPRefresh_EmptyTID(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	opts := fetchIdPOptions{
		TID:        "",
		HTTPClient: http.DefaultClient,
	}

	_, err := fetchIdPRefresh(ctx, store, opts)
	if err == nil {
		t.Fatal("expected error for empty TID, got nil")
	}
}
