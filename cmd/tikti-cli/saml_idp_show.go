package main

import (
	"context"
	"fmt"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

// showIdP is the testable core of the "saml idp show" command.
// It retrieves a single IdP record and returns it as a stable JSON-friendly map.
func showIdP(ctx context.Context, store saml.Store, tid string) (map[string]any, error) {
	if tid == "" {
		return nil, fmt.Errorf("--tid is required")
	}

	rec, err := store.GetIdP(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("fetching IdP record: %w", err)
	}

	return idpRecordToMap(rec), nil
}

// idpRecordToMap converts an IdPRecord to a stable JSON-friendly map.
func idpRecordToMap(rec saml.IdPRecord) map[string]any {
	return map[string]any{
		"tenant_id":           rec.TenantID,
		"entity_id":           rec.EntityID,
		"sso_url":             rec.SSOURL,
		"slo_url":             rec.SLOURL,
		"name_id_format":      rec.NameIDFormat,
		"num_signing_certs":   len(rec.SigningCerts),
		"num_encryption_certs": len(rec.EncryptionCerts),
		"attribute_map":       rec.AttributeMap,
		"metadata_url":        rec.MetadataURL,
		"last_fetched":        rec.LastFetched.Format(time.RFC3339),
	}
}
