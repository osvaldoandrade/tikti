package domain

import "time"

type Membership struct {
	Id        string    `json:"id"`
	TenantId  string    `json:"tenantId"`
	UserId    string    `json:"userId"`
	Roles     []string  `json:"roles"`
	CreatedAt time.Time `json:"createdAt"`
}
