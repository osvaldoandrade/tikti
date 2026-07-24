package domain

import "time"

type Membership struct {
	Id        string    `json:"id"`
	TenantId  string    `json:"tenantId"`
	UserId    string    `json:"userId"`
	Roles     []string  `json:"roles"`
	CreatedAt time.Time `json:"createdAt"`
}

type MembershipCreateReq struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

type MembershipRemoveReq struct {
	Email string `json:"email"`
}

type MembershipResp struct {
	Id        string    `json:"id"`
	TenantId  string    `json:"tenantId"`
	UserId    string    `json:"userId"`
	Email     string    `json:"email"`
	Roles     []string  `json:"roles"`
	CreatedAt time.Time `json:"createdAt"`
}

type MembershipRemoveResp struct {
	TenantId  string    `json:"tenantId"`
	UserId    string    `json:"userId"`
	Email     string    `json:"email"`
	RemovedAt time.Time `json:"removedAt"`
}

type TenantUserResp struct {
	Id         string     `json:"id"`
	Email      string     `json:"email"`
	Roles      []string   `json:"roles"`
	Status     UserStatus `json:"status"`
	AuthSource AuthSource `json:"authSource"`
	CreatedAt  time.Time  `json:"createdAt"`
}

type TenantUsersPage struct {
	Users         []TenantUserResp `json:"users"`
	NextPageToken string           `json:"nextPageToken"`
}
