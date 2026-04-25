package saml

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

// AuditRecord is the canonical audit payload for a SAML assertion decision.
// Fields match docs/saml/audit-schema.json (HLD App. H).
type AuditRecord struct {
	Event         string `json:"event"`
	SchemaVersion int    `json:"schemaVersion"`
	Timestamp     string `json:"ts"`
	TenantID      string `json:"tid"`
	RequestID     string `json:"requestID,omitempty"`
	AssertionID   string `json:"assertionID,omitempty"`
	NameID        string `json:"nameID,omitempty"`
	NameIDFormat  string `json:"nameIDFormat,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	Audience      string `json:"audience,omitempty"`
	Decision      string `json:"decision"`
	Reason        string `json:"reason,omitempty"`
	AttrHash      string `json:"attrHash,omitempty"`
	DurationMs    int    `json:"durationMs,omitempty"`
	ReplicaID     string `json:"replicaID,omitempty"`
	BuildSHA      string `json:"buildSHA,omitempty"`
}

// Emitter abstracts the destination of audit records so the transport
// can be swapped (log, queue, database) without changing callers.
type Emitter interface {
	Emit(ctx context.Context, rec AuditRecord) error
}

// LogEmitter writes audit records as JSON to the standard logger.
// It serves as the default Emitter implementation for the Tikti audit sink.
type LogEmitter struct{}

// Emit serialises rec to JSON and writes it via the standard logger.
func (LogEmitter) Emit(_ context.Context, rec AuditRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	log.Println(string(data))
	return nil
}

// AttrHash computes the deterministic hash of a SAML attribute map.
// The result is "sha256:" + hex(SHA-256(canonical)) where canonical is
// built by sorting keys, then sorting values per key, and joining them
// in a stable text representation. An empty or nil map returns an empty string.
func AttrHash(attrs map[string][]string) string {
	if len(attrs) == 0 {
		return ""
	}

	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		vals := make([]string, len(attrs[k]))
		copy(vals, attrs[k])
		sort.Strings(vals)
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strings.Join(vals, ","))
	}

	h := sha256.Sum256([]byte(b.String()))
	return fmt.Sprintf("sha256:%x", h)
}

// NewAcceptRecord builds an AuditRecord for an accepted assertion.
func NewAcceptRecord(tid string, assertion VerifiedAssertion, requestID string, audience string, dur time.Duration) AuditRecord {
	return AuditRecord{
		Event:         "saml.assertion",
		SchemaVersion: 1,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		TenantID:      tid,
		RequestID:     requestID,
		AssertionID:   assertion.AssertionID,
		NameID:        assertion.NameID,
		NameIDFormat:  assertion.NameIDFormat,
		Issuer:        assertion.IssuerEntityID,
		Audience:      audience,
		Decision:      "accept",
		Reason:        string(ReasonOK),
		AttrHash:      AttrHash(assertion.Attributes),
		DurationMs:    int(dur.Milliseconds()),
	}
}

// NewRejectRecord builds an AuditRecord for a rejected assertion.
func NewRejectRecord(tid string, requestID string, reason Reason, dur time.Duration) AuditRecord {
	return AuditRecord{
		Event:         "saml.assertion",
		SchemaVersion: 1,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		TenantID:      tid,
		RequestID:     requestID,
		Decision:      "reject",
		Reason:        string(reason),
		DurationMs:    int(dur.Milliseconds()),
	}
}
