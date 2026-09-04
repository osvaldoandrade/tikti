package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// readMetadata tests
// ---------------------------------------------------------------------------

func TestReadMetadata_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta.xml")
	want := []byte("<EntityDescriptor/>")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readMetadata("", path)
	if err != nil {
		t.Fatalf("readMetadata: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReadMetadata_URL(t *testing.T) {
	want := []byte("<EntityDescriptor/>")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	got, err := readMetadata(srv.URL, "")
	if err != nil {
		t.Fatalf("readMetadata: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReadMetadata_URLError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := readMetadata(srv.URL, "")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestReadMetadata_FileMissing(t *testing.T) {
	_, err := readMetadata("", "/nonexistent/path/meta.xml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// mergeCerts tests
// ---------------------------------------------------------------------------

func TestMergeCerts_NoDuplicates(t *testing.T) {
	old := [][]byte{[]byte("certA"), []byte("certB")}
	new := [][]byte{[]byte("certC"), []byte("certD")}

	merged := mergeCerts(old, new)
	if len(merged) != 4 {
		t.Fatalf("expected 4 certs, got %d", len(merged))
	}
	// New certs should come first.
	if string(merged[0]) != "certC" {
		t.Errorf("merged[0] = %q, want certC", merged[0])
	}
	if string(merged[1]) != "certD" {
		t.Errorf("merged[1] = %q, want certD", merged[1])
	}
	if string(merged[2]) != "certA" {
		t.Errorf("merged[2] = %q, want certA", merged[2])
	}
	if string(merged[3]) != "certB" {
		t.Errorf("merged[3] = %q, want certB", merged[3])
	}
}

func TestMergeCerts_Dedup(t *testing.T) {
	old := [][]byte{[]byte("certA"), []byte("certB")}
	new := [][]byte{[]byte("certB"), []byte("certC")}

	merged := mergeCerts(old, new)
	if len(merged) != 3 {
		t.Fatalf("expected 3 certs after dedup, got %d", len(merged))
	}
}

func TestMergeCerts_EmptyOld(t *testing.T) {
	new := [][]byte{[]byte("certA")}
	merged := mergeCerts(nil, new)
	if len(merged) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(merged))
	}
}

func TestMergeCerts_EmptyNew(t *testing.T) {
	old := [][]byte{[]byte("certA")}
	merged := mergeCerts(old, nil)
	if len(merged) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(merged))
	}
}

// ---------------------------------------------------------------------------
// extractOldCerts tests
// ---------------------------------------------------------------------------

func TestExtractOldCerts(t *testing.T) {
	certA := []byte("certA")
	certB := []byte("certB")
	resp := map[string]any{
		"signingCerts": []any{
			base64.StdEncoding.EncodeToString(certA),
			base64.StdEncoding.EncodeToString(certB),
		},
	}

	certs := extractOldCerts(resp)
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
	if string(certs[0]) != "certA" {
		t.Errorf("certs[0] = %q, want certA", certs[0])
	}
}

func TestExtractOldCerts_Missing(t *testing.T) {
	resp := map[string]any{}
	certs := extractOldCerts(resp)
	if certs != nil {
		t.Errorf("expected nil, got %v", certs)
	}
}

// ---------------------------------------------------------------------------
// loadAttrMap tests
// ---------------------------------------------------------------------------

func TestLoadAttrMap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "attrs.json")
	content := `{"email": ["mail", "email"], "name": ["displayName"]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := loadAttrMap(path)
	if err != nil {
		t.Fatalf("loadAttrMap: %v", err)
	}
	if len(m["email"]) != 2 {
		t.Errorf("expected 2 email mappings, got %d", len(m["email"]))
	}
	if len(m["name"]) != 1 {
		t.Errorf("expected 1 name mapping, got %d", len(m["name"]))
	}
}

func TestLoadAttrMap_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json}"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadAttrMap(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// Integration: rollback on parse failure
// ---------------------------------------------------------------------------

// TestSamlIdpUpdate_RollbackOnParseFailure verifies that the existing IdP
// record is never modified when new metadata fails to parse.
func TestSamlIdpUpdate_RollbackOnParseFailure(t *testing.T) {
	// Track whether the PUT endpoint was called.
	putCalled := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			// Return a fake existing IdP record.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tenantId": "t-001",
				"entityId": "https://idp.example.com",
				"signingCerts": []string{
					base64.StdEncoding.EncodeToString([]byte("old-cert")),
				},
			})
		case r.Method == http.MethodPut:
			putCalled = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "updated"})
		}
	}))
	defer srv.Close()

	// Write malformed metadata to a temp file.
	dir := t.TempDir()
	metaFile := filepath.Join(dir, "bad.xml")
	if err := os.WriteFile(metaFile, []byte("<not-valid-saml/>"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Build the command with the test server URL.
	var out bool
	cmd := samlIdpUpdateCmd(strPtr(""), &out)
	cmd.SetArgs([]string{
		"--tid", "t-001",
		"--metadata-file", metaFile,
	})

	// Override loadProfile to return a profile pointing to the test server.
	origLoadProfile := loadProfileFunc
	loadProfileFunc = func(_ string) (*profileEntry, error) {
		return &profileEntry{BaseURL: srv.URL, ApiKey: "test-key", AccessToken: "scoped-access-token"}, nil
	}
	defer func() { loadProfileFunc = origLoadProfile }()

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for malformed metadata, got nil")
	}
	if putCalled {
		t.Error("PUT was called — existing record would have been modified")
	}
}

// TestSamlIdpUpdate_SuccessPreservesCerts verifies that on successful update
// the old certs are merged with new certs (24-hour overlap).
func TestSamlIdpUpdate_SuccessPreservesCerts(t *testing.T) {
	// Read the Okta test metadata.
	metaXML, err := os.ReadFile("../../internal/saml/testdata/idp_okta.xml")
	if err != nil {
		t.Skipf("test metadata not available: %v", err)
	}

	oldCertDER := []byte("old-signing-cert-der")
	var putBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tenantId": "t-001",
				"entityId": "http://www.okta.com/exk123abc",
				"signingCerts": []string{
					base64.StdEncoding.EncodeToString(oldCertDER),
				},
			})
		case r.Method == http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&putBody)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "updated"})
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	metaFile := filepath.Join(dir, "okta.xml")
	if err := os.WriteFile(metaFile, metaXML, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bool
	cmd := samlIdpUpdateCmd(strPtr(""), &out)
	cmd.SetArgs([]string{
		"--tid", "t-001",
		"--metadata-file", metaFile,
	})

	origLoadProfile := loadProfileFunc
	loadProfileFunc = func(_ string) (*profileEntry, error) {
		return &profileEntry{BaseURL: srv.URL, ApiKey: "test-key", AccessToken: "scoped-access-token"}, nil
	}
	defer func() { loadProfileFunc = origLoadProfile }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if putBody == nil {
		t.Fatal("PUT was not called")
	}

	certs, ok := putBody["signingCerts"].([]any)
	if !ok {
		t.Fatal("signingCerts not in PUT body")
	}

	// Should have at least 2 certs: the new cert from metadata + old cert.
	if len(certs) < 2 {
		t.Errorf("expected >= 2 signing certs (old + new), got %d", len(certs))
	}

	// Old cert should be present.
	oldB64 := base64.StdEncoding.EncodeToString(oldCertDER)
	found := false
	for _, c := range certs {
		if c.(string) == oldB64 {
			found = true
			break
		}
	}
	if !found {
		t.Error("old cert not found in merged signing certs — 24h overlap not preserved")
	}
}

func strPtr(s string) *string { return &s }
