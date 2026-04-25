package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

// fetchIdPOptions holds parameters for the "saml idp fetch" command.
type fetchIdPOptions struct {
	TID         string
	MetadataURL string // override; when empty, uses the stored MetadataURL
	HTTPClient  httpGetter
}

// fetchIdPRefresh is the testable core of the "saml idp fetch" command.
// It re-downloads metadata from the IdP's metadataURL, re-parses it,
// preserves the tenant ID and attribute map, updates LastFetched, and
// persists the updated record.
func fetchIdPRefresh(ctx context.Context, store saml.Store, opts fetchIdPOptions) (*saml.IdPRecord, error) {
	if opts.TID == "" {
		return nil, errors.New("--tid is required")
	}

	// Load existing record.
	existing, err := store.GetIdP(ctx, opts.TID)
	if err != nil {
		return nil, fmt.Errorf("fetching existing IdP record: %w", err)
	}

	// Determine metadata URL.
	metaURL := opts.MetadataURL
	if metaURL == "" {
		metaURL = existing.MetadataURL
	}
	if metaURL == "" {
		return nil, errors.New("no metadata URL available; supply --metadata-url or register the IdP with one")
	}

	// Download fresh metadata.
	raw, err := fetchMetadata(opts.HTTPClient, metaURL)
	if err != nil {
		return nil, err
	}

	// Parse and validate the new metadata.
	rec, err := saml.ParseIdPMetadata(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing refreshed metadata: %w", err)
	}

	// Carry over tenant-specific fields.
	rec.TenantID = opts.TID
	rec.MetadataURL = metaURL
	rec.LastFetched = time.Now()

	// Preserve existing attribute map if not set by metadata.
	if rec.AttributeMap == nil && existing.AttributeMap != nil {
		rec.AttributeMap = existing.AttributeMap
	}

	// Persist the refreshed record.
	if err := store.PutIdP(ctx, *rec); err != nil {
		return nil, fmt.Errorf("persisting refreshed IdP: %w", err)
	}

	return rec, nil
}
