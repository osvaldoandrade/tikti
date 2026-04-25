package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

// domainAdd is the testable core of the "saml domain add" command.
// It maps an email domain to a tenant ID via Store.PutDomain. If the domain
// is already mapped to a different tenant the call returns an error (conflict).
func domainAdd(ctx context.Context, store saml.Store, domain, tid string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return fmt.Errorf("--domain is required")
	}
	if tid == "" {
		return fmt.Errorf("--tid is required")
	}

	// Check for an existing mapping.
	existing, err := store.GetDomain(ctx, domain)
	if err == nil && existing != "" {
		if existing == tid {
			// Idempotent — same tenant already owns this domain.
			return nil
		}
		return &cliError{
			msg:  fmt.Sprintf("domain %q is already mapped to tenant %q", domain, existing),
			exit: 1,
		}
	}

	return store.PutDomain(ctx, domain, tid)
}
