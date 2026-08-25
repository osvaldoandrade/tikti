package domain

import (
	"errors"
	"time"
)

var (
	// ErrWorkloadAccountConflict keeps registration replay failures opaque.
	ErrWorkloadAccountConflict = errors.New("workload account registration conflict")
	// ErrWorkloadAccountUnavailable hides storage and token-issuance details.
	ErrWorkloadAccountUnavailable = errors.New("workload account service unavailable")
)

// WorkloadAccountCredentials are transient and must never be persisted or logged.
type WorkloadAccountCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"` // #nosec G117 -- transient account credential.
}

// WorkloadAccountRegistrationResp is the exact public registration projection.
type WorkloadAccountRegistrationResp struct {
	LocalId   string    `json:"localId"`
	Email     string    `json:"email"`
	TenantID  string    `json:"tenantId"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
}

// WorkloadAccountSessionResp returns a tenant-scoped access token only to the
// authenticated workload BFF. Browsers receive it later as an HttpOnly cookie.
type WorkloadAccountSessionResp struct {
	AccessToken string `json:"accessToken"`
	TokenType   string `json:"tokenType"`
	LocalId     string `json:"localId"`
	Email       string `json:"email"`
	ExpiresIn   int    `json:"expiresIn"`
}
