package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

// ---------------------------------------------------------------------------
// In-memory Store for tests
// ---------------------------------------------------------------------------

type memStore struct {
	idps map[string]saml.IdPRecord
}

func newMemStore() *memStore {
	return &memStore{idps: make(map[string]saml.IdPRecord)}
}

func (m *memStore) PutIdP(_ context.Context, rec saml.IdPRecord) error {
	m.idps[rec.TenantID] = rec
	return nil
}

func (m *memStore) GetIdP(_ context.Context, tid string) (saml.IdPRecord, error) {
	rec, ok := m.idps[tid]
	if !ok {
		return saml.IdPRecord{}, saml.ErrIdPNotFound
	}
	return rec, nil
}

// Unused Store methods — satisfy the interface.
func (m *memStore) PutRequest(_ context.Context, _ saml.RequestRecord) error { return nil }
func (m *memStore) ConsumeRequest(_ context.Context, _ string) (saml.RequestRecord, bool, error) {
	return saml.RequestRecord{}, false, nil
}
func (m *memStore) ListIdPs(_ context.Context) ([]saml.IdPRecord, error)  { return nil, nil }
func (m *memStore) DeleteIdP(_ context.Context, tid string) error {
	delete(m.idps, tid)
	return nil
}
func (m *memStore) PutIndex(_ context.Context, _ string, _ saml.IndexRecord) error {
	return nil
}
func (m *memStore) GetIndex(_ context.Context, _ string) (saml.IndexRecord, error) {
	return saml.IndexRecord{}, nil
}
func (m *memStore) DeleteIndex(_ context.Context, _ string) error                        { return nil }
func (m *memStore) MarkSeen(_ context.Context, _ string, _ time.Duration) (bool, error)  { return false, nil }
func (m *memStore) PutDomain(_ context.Context, _, _ string) error                       { return nil }
func (m *memStore) GetDomain(_ context.Context, _ string) (string, error)                { return "", nil }
func (m *memStore) DeleteDomain(_ context.Context, _ string) error                       { return nil }

// Compile-time check.
var _ saml.Store = (*memStore)(nil)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestRegister_FromFile(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	opts := registerIdPOptions{
		TID:          "tenant-file",
		MetadataFile: filepath.Join("..", "..", "internal", "saml", "testdata", "idp_okta.xml"),
	}

	rec, err := registerIdP(ctx, store, opts)
	if err != nil {
		t.Fatalf("registerIdP: %v", err)
	}

	if rec.TenantID != "tenant-file" {
		t.Errorf("TenantID = %q, want %q", rec.TenantID, "tenant-file")
	}
	if rec.EntityID == "" {
		t.Error("EntityID is empty")
	}
	if rec.SSOURL == "" {
		t.Error("SSOURL is empty")
	}

	// Verify record was persisted.
	got, err := store.GetIdP(ctx, "tenant-file")
	if err != nil {
		t.Fatalf("GetIdP after persist: %v", err)
	}
	if got.EntityID != rec.EntityID {
		t.Errorf("persisted EntityID = %q, want %q", got.EntityID, rec.EntityID)
	}
}

func TestRegister_FromURL_WithMockServer(t *testing.T) {
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

	opts := registerIdPOptions{
		TID:         "tenant-url",
		MetadataURL: srv.URL + "/metadata",
		HTTPClient:  srv.Client(),
	}

	rec, err := registerIdP(ctx, store, opts)
	if err != nil {
		t.Fatalf("registerIdP: %v", err)
	}

	if rec.TenantID != "tenant-url" {
		t.Errorf("TenantID = %q, want %q", rec.TenantID, "tenant-url")
	}
	if rec.EntityID == "" {
		t.Error("EntityID is empty")
	}

	// Verify record was persisted.
	got, err := store.GetIdP(ctx, "tenant-url")
	if err != nil {
		t.Fatalf("GetIdP after persist: %v", err)
	}
	if got.EntityID != rec.EntityID {
		t.Errorf("persisted EntityID = %q, want %q", got.EntityID, rec.EntityID)
	}
}

func TestRegister_DuplicateTID_Rejected(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	// Pre-register an IdP for the same tenant.
	_ = store.PutIdP(ctx, saml.IdPRecord{TenantID: "dup-tenant", EntityID: "https://existing.example.com"})

	opts := registerIdPOptions{
		TID:          "dup-tenant",
		MetadataFile: filepath.Join("..", "..", "internal", "saml", "testdata", "idp_okta.xml"),
	}

	_, err := registerIdP(ctx, store, opts)
	if err == nil {
		t.Fatal("expected error for duplicate TID, got nil")
	}
	if got := err.Error(); got == "" {
		t.Error("error message is empty")
	}
}

// TestRegister_WithAttrMap verifies that an attribute map file is applied.
func TestRegister_WithAttrMap(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	// Write a temporary attribute map file.
	attrMap := map[string][]string{
		"email":  {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"},
		"groups": {"http://schemas.xmlsoap.org/claims/Group"},
	}
	attrJSON, _ := json.Marshal(attrMap)
	tmpDir := t.TempDir()
	attrFile := filepath.Join(tmpDir, "attr-map.json")
	if err := os.WriteFile(attrFile, attrJSON, 0o644); err != nil {
		t.Fatalf("writing attr map: %v", err)
	}

	opts := registerIdPOptions{
		TID:          "tenant-attr",
		MetadataFile: filepath.Join("..", "..", "internal", "saml", "testdata", "idp_okta.xml"),
		AttrMapFile:  attrFile,
	}

	rec, err := registerIdP(ctx, store, opts)
	if err != nil {
		t.Fatalf("registerIdP: %v", err)
	}
	if rec.AttributeMap == nil {
		t.Fatal("AttributeMap is nil")
	}
	if len(rec.AttributeMap["email"]) == 0 {
		t.Error("expected 'email' key in attribute map")
	}
}
