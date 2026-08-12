package domain

import "time"

// UserIdentity is the password-free projection returned by exact identity reads.
type UserIdentity struct {
	Id         string     `json:"localId"`
	Email      string     `json:"email"`
	Status     UserStatus `json:"status"`
	AuthSource AuthSource `json:"authSource"`
	CreatedAt  time.Time  `json:"createdAt"`
}
