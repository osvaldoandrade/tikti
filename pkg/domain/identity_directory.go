package domain

import "time"

// DirectoryUser is the password-free, token-free public projection of a user.
type DirectoryUser struct {
	ID                     string     `json:"id"`
	Email                  string     `json:"email"`
	Status                 UserStatus `json:"status"`
	AuthSource             AuthSource `json:"authSource"`
	HomeTenantID           string     `json:"homeTenantId,omitempty"`
	PasswordChangeRequired bool       `json:"passwordChangeRequired"`
	CreatedAt              time.Time  `json:"createdAt"`
}

type DirectoryUserPage struct {
	Users         []DirectoryUser `json:"users"`
	NextPageToken string          `json:"nextPageToken,omitempty"`
}

type DirectoryUserCreateReq struct {
	Email             string `json:"email"`
	TemporaryPassword string `json:"temporaryPassword"`
}

type TemporaryPasswordChangeReq struct {
	Email             string `json:"email"`
	TemporaryPassword string `json:"temporaryPassword"`
	NewPassword       string `json:"newPassword"`
}

type IdentityGroupStatus string

const (
	IdentityGroupStatusActive   IdentityGroupStatus = "ACTIVE"
	IdentityGroupStatusDisabled IdentityGroupStatus = "DISABLED"
)

// IdentityGroup is global and reusable. Tenant authority is granted by a
// separate group assignment; groups themselves never nest.
type IdentityGroup struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Status      IdentityGroupStatus `json:"status"`
	MemberCount int                 `json:"memberCount"`
	Version     int64               `json:"version"`
	CreatedAt   time.Time           `json:"createdAt"`
	UpdatedAt   time.Time           `json:"updatedAt"`
}

// IdentityGroupDetail is the complete group projection. DirectoryUser keeps
// member credentials and internal authentication state out of the response.
type IdentityGroupDetail struct {
	IdentityGroup
	Members []DirectoryUser `json:"members"`
}

type IdentityGroupPage struct {
	Groups        []IdentityGroup `json:"groups"`
	NextPageToken string          `json:"nextPageToken,omitempty"`
}

type IdentityGroupCreateReq struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type IdentityGroupPatchReq struct {
	Name        *string              `json:"name,omitempty"`
	Description *string              `json:"description,omitempty"`
	Status      *IdentityGroupStatus `json:"status,omitempty"`
}

type AccessPrincipalType string

const (
	AccessPrincipalUser  AccessPrincipalType = "USER"
	AccessPrincipalGroup AccessPrincipalType = "GROUP"
)

// AccessAssignment is the mutable, versioned source of tenant access.
type AccessAssignment struct {
	TenantID      string              `json:"tenantId"`
	PrincipalType AccessPrincipalType `json:"principalType"`
	PrincipalID   string              `json:"principalId"`
	Roles         []string            `json:"roles"`
	Version       int64               `json:"version"`
	CreatedAt     time.Time           `json:"createdAt"`
	UpdatedAt     time.Time           `json:"updatedAt"`
}

type AccessAssignmentPage struct {
	Assignments   []AccessAssignment `json:"assignments"`
	NextPageToken string             `json:"nextPageToken,omitempty"`
}

type AccessAssignmentPutReq struct {
	Roles []string `json:"roles"`
}

type AccessProvenance struct {
	Type              string   `json:"type"`
	Roles             []string `json:"roles"`
	AssignmentVersion int64    `json:"assignmentVersion"`
	GroupID           string   `json:"groupId,omitempty"`
	GroupName         string   `json:"groupName,omitempty"`
}

type EffectiveTenantAccess struct {
	TenantID   string             `json:"tenantId"`
	Roles      []string           `json:"roles"`
	Provenance []AccessProvenance `json:"provenance"`
}

type DirectoryUserAccess struct {
	User    DirectoryUser           `json:"user"`
	Tenants []EffectiveTenantAccess `json:"tenants"`
}

type IdentityBackfillResult struct {
	UsersIndexed      int `json:"usersIndexed"`
	AssignmentsCopied int `json:"assignmentsCopied"`
}
