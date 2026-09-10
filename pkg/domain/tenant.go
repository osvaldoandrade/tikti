package domain

import "time"

type TenantStatus string
type TenantType string

const (
	MasterTenantID         = "local-tenant"
	MasterTenantName       = "Code Foundry"
	RetiredDefaultTenantID = "default"
)

const (
	TenantStatusActive   TenantStatus = "ACTIVE"
	TenantStatusDisabled TenantStatus = "DISABLED"
	TenantTypeMaster     TenantType   = "MASTER"
	TenantTypeWorkload   TenantType   = "WORKLOAD"
)

type Tenant struct {
	Id        string       `json:"id"`
	Slug      string       `json:"slug"`
	Name      string       `json:"name"`
	Status    TenantStatus `json:"status"`
	CreatedAt time.Time    `json:"createdAt"`
	// RetiredAt is a retained identity tombstone, never a public tenant field.
	RetiredAt *time.Time `json:"retiredAt,omitempty"`
}

type TenantCreateReq struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type TenantResp struct {
	Id         string       `json:"id"`
	Slug       string       `json:"slug"`
	Name       string       `json:"name"`
	Status     TenantStatus `json:"status"`
	CreatedAt  time.Time    `json:"createdAt"`
	TenantType TenantType   `json:"tenantType"`
}

// TenantsPage is the administrative, paginated tenant directory projection.
type TenantsPage struct {
	Tenants       []TenantResp `json:"tenants"`
	NextPageToken string       `json:"nextPageToken"`
}
