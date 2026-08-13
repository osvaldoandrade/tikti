package domain

import "slices"

type ClientType string

type GrantType string

const (
	ClientTypeConfidential ClientType = "CONFIDENTIAL"
	ClientTypePublic       ClientType = "PUBLIC"
	ClientTypeService      ClientType = "SERVICE"

	GrantTypeTokenExchange GrantType = "token_exchange"

	ClientStatusActive             = "ACTIVE"
	CodeAdminAudienceClientID      = "code-admin-api"
	CodeAdminAudienceClientManager = "tikti:code-admin-audience:v1"
)

type Client struct {
	Id                string     `json:"clientId"`
	TenantId          string     `json:"tenantId"`
	SecretHash        string     `json:"secretHash,omitempty"`
	Type              ClientType `json:"type"`
	AllowedGrantTypes []string   `json:"allowedGrantTypes"`
	DefaultScopes     []string   `json:"defaultScopes"`
	Status            string     `json:"status"`
	ManagedBy         string     `json:"managedBy,omitempty"`
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

// ManagedAudienceClientEnsureReq carries the server-selected scope ceiling.
type ManagedAudienceClientEnsureReq struct {
	DefaultScopes []string `json:"defaultScopes"`
}

// ManagedAudienceClientResp intentionally excludes credentials and hashes.
type ManagedAudienceClientResp struct {
	ClientId          string     `json:"clientId"`
	TenantId          string     `json:"tenantId"`
	Type              ClientType `json:"type"`
	AllowedGrantTypes []string   `json:"allowedGrantTypes"`
	DefaultScopes     []string   `json:"defaultScopes"`
	Status            string     `json:"status"`
}

// IsManagedCodeAdminAudience reports whether both immutable identities match.
func IsManagedCodeAdminAudience(tenantID string, client *Client) bool {
	return client != nil && client.Id == CodeAdminAudienceClientID && client.TenantId == tenantID &&
		client.SecretHash == "" && client.Type == ClientTypeService && client.Status == ClientStatusActive &&
		client.ManagedBy == CodeAdminAudienceClientManager &&
		slices.Equal(client.AllowedGrantTypes, []string{string(GrantTypeTokenExchange)})
}
