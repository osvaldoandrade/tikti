package domain

type ClientType string

type GrantType string

const (
	ClientTypeConfidential ClientType = "CONFIDENTIAL"
	ClientTypePublic       ClientType = "PUBLIC"
	ClientTypeService      ClientType = "SERVICE"

	GrantTypeTokenExchange GrantType = "token_exchange"
)

type Client struct {
	Id                string     `json:"clientId"`
	TenantId          string     `json:"tenantId"`
	SecretHash        string     `json:"secretHash"`
	Type              ClientType `json:"type"`
	AllowedGrantTypes []string   `json:"allowedGrantTypes"`
	DefaultScopes     []string   `json:"defaultScopes"`
	Status            string     `json:"status"`
}

type ClientCreateReq struct {
	ClientId          string   `json:"clientId"`
	Type              string   `json:"type"`
	AllowedGrantTypes []string `json:"allowedGrantTypes"`
	DefaultScopes     []string `json:"defaultScopes"`
}

type ClientResp struct {
	ClientId          string   `json:"clientId"`
	Type              string   `json:"type"`
	AllowedGrantTypes []string `json:"allowedGrantTypes"`
	DefaultScopes     []string `json:"defaultScopes"`
	Secret            string   `json:"secret,omitempty"`
}
