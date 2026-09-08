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

	"github.com/go-redis/redis/v8"
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
	SubjectHash   string `json:"subjectHash,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	Audience      string `json:"audience,omitempty"`
	Decision      string `json:"decision"`
	Phase         string `json:"phase,omitempty"`
	Reason        string `json:"reason,omitempty"`
	AttrHash      string `json:"attrHash,omitempty"`
	DurationMs    int    `json:"durationMs,omitempty"`
	ReplicaID     string `json:"replicaID,omitempty"`
	BuildSHA      string `json:"buildSHA,omitempty"`
}

// AuditSubjectHash preserves tenant-local correlation without writing the raw
// external subject (often an email address) to logs or audit storage.
func AuditSubjectHash(tenantID, externalSubject string) string {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(externalSubject) == "" {
		return ""
	}
	digest := sha256.Sum256([]byte("saml-audit-subject-v1\x00" + tenantID + "\x00" + externalSubject))
	return fmt.Sprintf("sha256:%x", digest)
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

// RedisAuditEmitter persists bounded, redacted SAML decisions before handing
// them to the operational log sink. Records expire so authentication traffic
// cannot grow Redis without bound; the key contains only a content digest.
type RedisAuditEmitter struct {
	client *redis.Client
	ttl    time.Duration
	next   Emitter
}

func NewRedisAuditEmitter(client *redis.Client, ttl time.Duration, next Emitter) Emitter {
	return &RedisAuditEmitter{client: client, ttl: ttl, next: next}
}

func (e *RedisAuditEmitter) Emit(ctx context.Context, rec AuditRecord) error {
	if e == nil || e.client == nil || e.ttl < time.Hour || rec.Event != "saml.assertion" ||
		rec.SchemaVersion != 1 || strings.TrimSpace(rec.TenantID) == "" && rec.Decision == "accept" ||
		(rec.Decision != "accept" && rec.Decision != "reject") ||
		(rec.Phase != "" && rec.Phase != "intent" && rec.Phase != "outcome") {
		return fmt.Errorf("audit: invalid durable record")
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("audit: marshal durable record: %w", err)
	}
	digest := sha256.Sum256(append([]byte("saml-audit-record-v1\x00"), payload...))
	key := fmt.Sprintf("saml:audit:v1:%x", digest[:])
	if _, err := e.client.SetNX(ctx, key, payload, e.ttl).Result(); err != nil {
		return fmt.Errorf("audit: persist durable record: %w", err)
	}
	if e.next != nil {
		return e.next.Emit(ctx, rec)
	}
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
	return newAcceptRecord("outcome", tid, assertion, requestID, audience, dur)
}

// NewAcceptIntentRecord is persisted after cryptographic/replay validation but
// before JIT provisioning can create a user or change authority. A later
// outcome record completes the audit pair.
func NewAcceptIntentRecord(tid string, assertion VerifiedAssertion, requestID string, audience string, dur time.Duration) AuditRecord {
	return newAcceptRecord("intent", tid, assertion, requestID, audience, dur)
}

func newAcceptRecord(phase, tid string, assertion VerifiedAssertion, requestID string, audience string, dur time.Duration) AuditRecord {
	return AuditRecord{
		Event:         "saml.assertion",
		SchemaVersion: 1,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		TenantID:      tid,
		RequestID:     requestID,
		AssertionID:   assertion.AssertionID,
		SubjectHash:   AuditSubjectHash(tid, assertion.NameID),
		Issuer:        assertion.IssuerEntityID,
		Audience:      audience,
		Decision:      "accept",
		Phase:         phase,
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
		Phase:         "outcome",
		Reason:        string(reason),
		DurationMs:    int(dur.Milliseconds()),
	}
}

// NewRejectOutcomeRecord closes a previously persisted accept intent when a
// local bridge, authority or session-index step fails after the assertion was
// fully validated. It retains only deterministic safe hashes and identifiers,
// never the raw external subject or assertion attributes.
func NewRejectOutcomeRecord(tid string, assertion VerifiedAssertion, requestID string, audience string, reason Reason, dur time.Duration) AuditRecord {
	record := newAcceptRecord("outcome", tid, assertion, requestID, audience, dur)
	record.Decision = "reject"
	record.Reason = string(reason)
	return record
}
