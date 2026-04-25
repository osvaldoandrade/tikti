package saml

import (
	"context"
	"time"
)

// Store abstracts the persistence layer for SAML state. 13 methods across
// four record families: requests, IdPs, session indexes, and replay marks.
type Store interface {
	PutRequest(ctx context.Context, rec RequestRecord) error
	ConsumeRequest(ctx context.Context, id string) (RequestRecord, bool, error)

	PutIdP(ctx context.Context, rec IdPRecord) error
	GetIdP(ctx context.Context, tid string) (IdPRecord, error)
	ListIdPs(ctx context.Context) ([]IdPRecord, error)
	DeleteIdP(ctx context.Context, tid string) error

	PutIndex(ctx context.Context, nameID string, rec IndexRecord) error
	GetIndex(ctx context.Context, nameID string) (IndexRecord, error)
	DeleteIndex(ctx context.Context, nameID string) error

	MarkSeen(ctx context.Context, assertionID string, ttl time.Duration) (bool, error)

	PutDomain(ctx context.Context, domain, tid string) error
	GetDomain(ctx context.Context, domain string) (string, error)
	DeleteDomain(ctx context.Context, domain string) error
}

// RequestRecord represents a pending SAML AuthnRequest stored until the
// corresponding Response arrives at the ACS endpoint.
type RequestRecord struct {
	ID           string
	TenantID     string
	RelayState   string
	ACSURL       string
	IssueInstant time.Time
}

// IndexRecord maps a SAML NameID to local session data, used for
// Single Logout to correlate the IdP session with the local session.
type IndexRecord struct {
	TenantID     string
	Subject      string
	SessionIndex string
	NotOnOrAfter time.Time
}
