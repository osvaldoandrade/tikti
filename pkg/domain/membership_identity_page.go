package domain

// MembershipIdentitiesPage is a safe page of exact tenant assignments.
type MembershipIdentitiesPage struct {
	Memberships   []MembershipIdentity `json:"memberships"`
	NextPageToken string               `json:"nextPageToken"`
}
