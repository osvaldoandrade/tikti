package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

// domainRemove is the testable core of the "saml domain remove" command.
// It deletes the email-domain → tenant mapping via Store.DeleteDomain.
func domainRemove(ctx context.Context, store saml.Store, domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return fmt.Errorf("--domain is required")
	}

	return store.DeleteDomain(ctx, domain)
}
