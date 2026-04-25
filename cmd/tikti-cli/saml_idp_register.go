package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

// httpGetter abstracts HTTP GET for testability.
type httpGetter interface {
	Get(url string) (*http.Response, error)
}

// registerIdPOptions holds the parameters for IdP registration.
type registerIdPOptions struct {
	TID          string
	MetadataURL  string
	MetadataFile string
	AttrMapFile  string
	HTTPClient   httpGetter
}

// registerIdP is the testable core of the "saml idp register" command.
// It fetches or reads metadata, parses and validates it, checks for
// duplicate tenant IDs, applies an optional attribute map, and persists
// the record via the provided store.
func registerIdP(ctx context.Context, store saml.Store, opts registerIdPOptions) (*saml.IdPRecord, error) {
	if opts.TID == "" {
		return nil, errors.New("--tid is required")
	}
	if opts.MetadataURL == "" && opts.MetadataFile == "" {
		return nil, errors.New("--metadata-url or --metadata-file is required")
	}

	// Reject duplicate tenant ID.
	_, err := store.GetIdP(ctx, opts.TID)
	if err == nil {
		return nil, fmt.Errorf("IdP already registered for tenant %q", opts.TID)
	}
	if !errors.Is(err, saml.ErrIdPNotFound) {
		return nil, fmt.Errorf("checking existing IdP: %w", err)
	}

	// Obtain raw metadata bytes.
	var raw []byte
	if opts.MetadataFile != "" {
		raw, err = os.ReadFile(opts.MetadataFile)
	} else {
		raw, err = fetchMetadata(opts.HTTPClient, opts.MetadataURL)
	}
	if err != nil {
		return nil, err
	}

	// Parse and validate.
	rec, err := saml.ParseIdPMetadata(raw)
	if err != nil {
		return nil, err
	}
	rec.TenantID = opts.TID

	// Apply optional attribute map.
	if opts.AttrMapFile != "" {
		mapData, err := os.ReadFile(opts.AttrMapFile)
		if err != nil {
			return nil, fmt.Errorf("reading attribute map: %w", err)
		}
		var attrMap map[string][]string
		if err := json.Unmarshal(mapData, &attrMap); err != nil {
			return nil, fmt.Errorf("parsing attribute map: %w", err)
		}
		rec.AttributeMap = attrMap
	}

	// Persist.
	if err := store.PutIdP(ctx, *rec); err != nil {
		return nil, err
	}

	return rec, nil
}

// fetchMetadata downloads IdP metadata from the given URL.
func fetchMetadata(client httpGetter, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching metadata: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}


