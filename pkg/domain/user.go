package domain

import "time"

// UserStatus enumerates the possible lifecycle states of a stored user.
type UserStatus string

const (
	// UserStatusActive marks accounts that can authenticate and receive tokens.
	UserStatusActive UserStatus = "ACTIVE"
	// UserStatusInactive covers accounts created but not yet activated.
	UserStatusInactive UserStatus = "INACTIVE"
	// UserStatusSuspended blocks sign-in because of policy or security actions.
	UserStatusSuspended UserStatus = "SUSPENDED"
)

// UserRole captures authorization tiers enforced at the application layer.
type UserRole string

const (
	// RoleAdmin maps to the super-admin role with permission to manage accounts.
	RoleAdmin UserRole = "ADMIN"
	// RoleCompanyAdmin can manage accounts within its company boundary.
	RoleCompanyAdmin UserRole = "COMPANY_ADMIN"
	// RoleCompanyEmployee is a standard user role for daily operations.
	RoleCompanyEmployee UserRole = "COMPANY_EMPLOYEE"
)

const (
	// PlatformTenantAdminScope is the global tenant-administration capability.
	PlatformTenantAdminScope = "code-admin:tenants:admin"
	// PlatformPrivilegeClaim records that Tikti issued a global privilege from
	// the persisted platform-admin role rather than from a tenant-scoped role.
	PlatformPrivilegeClaim = "tikti_platform_privilege"
	// PlatformPrivilegeAdmin is the only provenance accepted for global tenant
	// membership administration.
	PlatformPrivilegeAdmin = "platform-admin"
)

// AuthSource distinguishes how a user was provisioned.
type AuthSource string

const (
	// AuthSourcePassword is the default for users created via the password sign-up flow.
	AuthSourcePassword AuthSource = "password"
	// AuthSourceSAML marks users provisioned through a SAML identity provider.
	AuthSourceSAML AuthSource = "saml"
)

// MergeStrategy controls how UpsertFromSAML resolves an existing user.
type MergeStrategy string

const (
	// MergeStrategyEmail matches an existing password user by (tid, email) and
	// converts it to a SAML user. This is the default.
	MergeStrategyEmail MergeStrategy = "email"
	// MergeStrategyExternalSubject only merges when the SAML external subject
	// already exists; no email-based merge is attempted.
	MergeStrategyExternalSubject MergeStrategy = "externalSubject"
	// MergeStrategyNone disables merge entirely; a new user is always created
	// when no prior SAML subject match is found.
	MergeStrategyNone MergeStrategy = "none"
)

// User represents the canonical user document stored in Redis and exposed to clients.
type User struct {
	Id              string     `json:"localId"`
	Email           string     `json:"email"`
	Password        string     `json:"password"`
	Role            UserRole   `json:"role"`
	Status          UserStatus `json:"status"`
	CompanyId       *string    `json:"companyId,omitempty"`
	TokenVersion    int        `json:"tokenVersion,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
	AuthSource      AuthSource `json:"authSource"`
	ExternalSubject string     `json:"externalSubject"`
}

// SignUpReq holds the payload expected when an admin creates a new user.
type SignUpReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role,omitempty"`
}

// SignUpResp captures the subset of data echoed back after a successful creation.
type SignUpResp struct {
	LocalId   string    `json:"localId"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
}

// SignInReq represents the password-based sign-in payload.
type SignInReq struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

// SignInWithOobCodeReq authenticates a user using an out-of-band code sent via email.
type SignInWithOobCodeReq struct {
	Email             string `json:"email"`
	OobCode           string `json:"oobCode"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

// SignInResp mirrors Firebase's response with token, identifiers and expiration.
type SignInResp struct {
	IdToken   string `json:"idToken"`
	Email     string `json:"email"`
	LocalId   string `json:"localId"`
	ExpiresIn int    `json:"expiresIn"`
}

// LookupReq is a Firebase-compatible request body to resolve an idToken.
type LookupReq struct {
	IdToken string `json:"idToken"`
}

// UserInfo provides lightweight identity details returned by lookup requests.
type UserInfo struct {
	LocalId string `json:"localId"`
	Email   string `json:"email"`
	Role    string `json:"role,omitempty"`
	Status  string `json:"status,omitempty"`
	Tenant  string `json:"tenantId,omitempty"`
}

// LookupResp is the JSON document returned to clients calling /lookup.
type LookupResp struct {
	Users []UserInfo `json:"users"`
}

// TokenExchangeReq holds request fields to exchange an idToken for a scoped access token.
type TokenExchangeReq struct {
	IdToken    string   `json:"idToken"`
	Audience   string   `json:"audience"`
	Scopes     []string `json:"scopes,omitempty"`
	EventTypes []string `json:"eventTypes,omitempty"`
	TTLSeconds int      `json:"ttlSeconds,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	TenantID   string   `json:"tenantId,omitempty"`
}

// TokenExchangeResp returns the issued access token and metadata.
type TokenExchangeResp struct {
	AccessToken string `json:"accessToken"`
	TokenType   string `json:"tokenType"`
	ExpiresIn   int    `json:"expiresIn"`
}

// UpdateReq contains optional fields that can be changed for the authenticated user.
type UpdateReq struct {
	IdToken  string `json:"idToken"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

// UpdateResp echoes the fresh identifiers after a successful update.
type UpdateResp struct {
	LocalId string `json:"localId"`
	Email   string `json:"email"`
}

// DeleteReq is the minimal payload required to delete the authenticated user.
type DeleteReq struct {
	IdToken string `json:"idToken"`
}

type StatusResp struct {
	LocalId string `json:"localId"`
	Email   string `json:"email"`
	Status  string `json:"status"`
}

type RevokeResp struct {
	LocalId      string `json:"localId"`
	Email        string `json:"email"`
	TokenVersion int    `json:"tokenVersion"`
	RevokedAt    string `json:"revokedAt"`
}

// SendOobReq requests an out-of-band code for password resets or email sign-in flows.
type SendOobReq struct {
	RequestType string `json:"requestType"`
	Email       string `json:"email"`
}

// SendOobResp conveys the generated code and metadata for clients to process.
type SendOobResp struct {
	Kind    string `json:"kind"`
	Email   string `json:"email"`
	OobCode string `json:"oobCode"`
}

// SendOobTenantResp returns an out-of-band code for workflows that orchestrate delivery externally.
type SendOobTenantResp struct {
	Kind        string `json:"kind"`
	Email       string `json:"email"`
	RequestType string `json:"requestType"`
	ExpiresIn   int    `json:"expiresIn"`
	OobCode     string `json:"oobCode"`
}

// ResetPwdReq carries the OOB code and new password for password reset flows.
type ResetPwdReq struct {
	OobCode     string `json:"oobCode"`
	NewPassword string `json:"newPassword"`
}
