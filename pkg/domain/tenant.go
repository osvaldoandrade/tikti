package domain

import "time"

type TenantStatus string

const (
	TenantStatusActive   TenantStatus = "ACTIVE"
	TenantStatusDisabled TenantStatus = "DISABLED"
)

type Tenant struct {
	Id        string       `json:"id"`
	Slug      string       `json:"slug"`
	Name      string       `json:"name"`
	Status    TenantStatus `json:"status"`
	CreatedAt time.Time    `json:"createdAt"`
}

type TenantCreateReq struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type TenantResp struct {
	Id        string       `json:"id"`
	Slug      string       `json:"slug"`
	Name      string       `json:"name"`
	Status    TenantStatus `json:"status"`
	CreatedAt time.Time    `json:"createdAt"`
}
