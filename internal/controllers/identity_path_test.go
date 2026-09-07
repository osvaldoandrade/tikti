package controllers

import (
	"strings"
	"testing"
)

func TestCanonicalIdentityPaths(t *testing.T) {
	for value, want := range map[string]bool{
		"local-tenant": true,
		"tenant_1":     false,
		"-tenant":      false,
		"tenant-":      false,
		"":             false,
	} {
		if got := canonicalTenantIDPath(value); got != want {
			t.Errorf("canonicalTenantIDPath(%q) = %t, want %t", value, got, want)
		}
	}

	for value, want := range map[string]bool{
		".": false, "..": false, "": false, "A": true, "a..b": true,
		strings.Repeat("a", 128): true, strings.Repeat("a", 129): false, "user/bad": false,
	} {
		if got := canonicalDirectoryIDPath(value); got != want {
			t.Errorf("canonicalDirectoryIDPath(%q) = %t, want %t", value, got, want)
		}
	}
}
