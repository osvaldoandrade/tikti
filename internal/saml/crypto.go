package saml

import (
	"bytes"
	"fmt"

	"github.com/beevik/etree"
)

// parseXML is the centralized XML parser for all SAML payloads.
// It rejects XXE attack vectors (DOCTYPE, ENTITY declarations) before
// parsing and disables entity expansion in the etree reader.
func parseXML(raw []byte) (*etree.Document, error) {
	if containsXXE(raw) {
		return nil, fmt.Errorf("%w", ErrXXE)
	}

	doc := etree.NewDocument()
	doc.ReadSettings = etree.ReadSettings{
		// Do not map any custom entities — prevents expansion.
		Entity: nil,
		// Strict mode: reject malformed XML.
		Permissive: false,
		// Validate that the input is well-formed XML.
		ValidateInput: true,
	}

	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("saml: xml parse: %w", err)
	}
	return doc, nil
}

// containsXXE scans raw XML bytes for DOCTYPE or ENTITY declarations
// (case-insensitive) that signal an XXE attack attempt.
func containsXXE(raw []byte) bool {
	lower := bytes.ToLower(raw)
	return bytes.Contains(lower, []byte("<!doctype")) ||
		bytes.Contains(lower, []byte("<!entity"))
}
