package main

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

// listIdPs is the testable core of the "saml idp list" command.
// It retrieves all IdP records from the store and returns them as a
// stable JSON-friendly slice of maps.
func listIdPs(ctx context.Context, store saml.Store) ([]map[string]any, error) {
	records, err := store.ListIdPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing IdPs: %w", err)
	}

	result := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		result = append(result, map[string]any{
			"tenant_id":    rec.TenantID,
			"entity_id":    rec.EntityID,
			"last_fetched": rec.LastFetched.Format(time.RFC3339),
		})
	}
	return result, nil
}

// formatIdPTable renders a slice of IdP summary maps as a plain-text table.
func formatIdPTable(records []map[string]any) string {
	var buf strings.Builder
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TENANT ID\tENTITY ID\tLAST FETCHED")
	for _, r := range records {
		fmt.Fprintf(tw, "%s\t%s\t%s\n",
			r["tenant_id"],
			r["entity_id"],
			r["last_fetched"],
		)
	}
	tw.Flush()
	return buf.String()
}
