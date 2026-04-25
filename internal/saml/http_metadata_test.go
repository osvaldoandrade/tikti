package saml

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// metadataStubProvider is a test double that returns fixed SP metadata bytes.
type metadataStubProvider struct {
	stubProvider // embed for unused interface methods
	data         []byte
	err          error
}

func (p *metadataStubProvider) SPMetadata(_ context.Context) ([]byte, error) {
	return p.data, p.err
}

// TestMetadata_200_WithCorrectContentType verifies that the Metadata handler
// returns HTTP 200 with the required Content-Type and Cache-Control headers.
func TestMetadata_200_WithCorrectContentType(t *testing.T) {
	golden, err := os.ReadFile("testdata/sp_metadata.xml")
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}

	h := NewHandler(&metadataStubProvider{data: golden})

	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	rec := httptest.NewRecorder()
	h.Metadata(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	wantCT := "application/samlmetadata+xml; charset=utf-8"
	if got := rec.Header().Get("Content-Type"); got != wantCT {
		t.Errorf("Content-Type = %q, want %q", got, wantCT)
	}

	wantCC := "public, max-age=86400"
	if got := rec.Header().Get("Cache-Control"); got != wantCC {
		t.Errorf("Cache-Control = %q, want %q", got, wantCC)
	}
}

// TestMetadata_BytesGolden verifies that the Metadata handler response body
// matches the golden file testdata/sp_metadata.xml byte-for-byte.
func TestMetadata_BytesGolden(t *testing.T) {
	golden, err := os.ReadFile("testdata/sp_metadata.xml")
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}

	h := NewHandler(&metadataStubProvider{data: golden})

	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	rec := httptest.NewRecorder()
	h.Metadata(rec, req)

	if !bytes.Equal(rec.Body.Bytes(), golden) {
		t.Fatalf("body differs from golden file.\ngot (%d bytes):\n%s\nwant (%d bytes):\n%s",
			len(rec.Body.Bytes()), rec.Body.Bytes(), len(golden), golden)
	}
}
