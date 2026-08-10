package domain

type RoleScope string

const (
	RoleScopeGlobal   RoleScope = "GLOBAL"
	RoleScopeTenant   RoleScope = "TENANT"
	RoleScopeResource RoleScope = "RESOURCE"
)

type Role struct {
	Name        string    `json:"name"`
	Scope       RoleScope `json:"scope"`
	TenantId    string    `json:"tenantId,omitempty"`
	ResourceId  string    `json:"resourceId,omitempty"`
	Permissions []string  `json:"permissions"`
}

type RoleCreateReq struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// RolePutReq is the immutable definition accepted by deterministic role creation.
type RolePutReq struct {
	Permissions []string `json:"permissions"`
}

type RoleResp struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}
