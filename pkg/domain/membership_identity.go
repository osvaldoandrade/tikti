package domain

import "time"

// MembershipIdentity is a safe, composed projection for one tenant assignment.
type MembershipIdentity struct {
	Id        string       `json:"id"`
	TenantId  string       `json:"tenantId"`
	UserId    string       `json:"userId"`
	Roles     []string     `json:"roles"`
	CreatedAt time.Time    `json:"createdAt"`
	User      UserIdentity `json:"user"`
}
