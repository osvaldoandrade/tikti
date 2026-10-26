package domain

import "slices"

type ClientType string

type GrantType string

const (
	ClientTypeConfidential ClientType = "CONFIDENTIAL"
	ClientTypePublic       ClientType = "PUBLIC"
	ClientTypeService      ClientType = "SERVICE"

	GrantTypeTokenExchange GrantType = "token_exchange"

	ClientStatusActive = "ACTIVE"
	// ClientStatusInactive is used only by the managed AI audience: a disabled
	// tenant AI feature keeps its credential-free record but cannot exchange.
	ClientStatusInactive            = "INACTIVE"
	CodeAdminAudienceClientID       = "code-admin-api"
	CodeAdminAudienceClientManager  = "tikti:code-admin-audience:v1"
	WorkloadAccountBFFClientManager = "tikti:workload-account-bff:v1"
	// AIGatewayAudienceClientID is the AI token audience protocol identifier
	// (JWT aud). It names no repository or image and must not be renamed.
	AIGatewayAudienceClientID      = "code-llm-service"
	AIGatewayAudienceClientManager = "tikti:ai-gateway-audience:v1"
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

// IsBootstrapLegacyAudience reports whether client is exactly the
// credential-free, unmanaged PUBLIC token-exchange audience that the
// installation bootstrap writes for clientID in tenantID. Generic client
// creation always stores a secret, so only the bootstrap produces this shape.
// It deliberately ignores DefaultScopes; callers validate the ceiling.
func IsBootstrapLegacyAudience(tenantID, clientID string, client *Client) bool {
	return client != nil && client.Id == clientID && client.TenantId == tenantID &&
		client.SecretHash == "" && client.Type == ClientTypePublic && client.Status == ClientStatusActive &&
		client.ManagedBy == "" && slices.Equal(client.AllowedGrantTypes, []string{string(GrantTypeTokenExchange)})
}

// IsBootstrapLegacyCodeAdminAudience reports whether client is the bootstrap's
// legacy PUBLIC code-admin-api home audience of tenantID.
func IsBootstrapLegacyCodeAdminAudience(tenantID string, client *Client) bool {
	return IsBootstrapLegacyAudience(tenantID, CodeAdminAudienceClientID, client)
}

// IsManagedWorkloadAccountAudience reports whether the credential-free client
// is owned by the workload account BFF bootstrap contract.
func IsManagedWorkloadAccountAudience(tenantID string, client *Client) bool {
	return client != nil && client.Id != "" && client.Id != CodeAdminAudienceClientID &&
		client.Id != AIGatewayAudienceClientID && client.TenantId == tenantID &&
		client.SecretHash == "" && client.Type == ClientTypeService && client.Status == ClientStatusActive &&
		client.ManagedBy == WorkloadAccountBFFClientManager &&
		slices.Equal(client.AllowedGrantTypes, []string{string(GrantTypeTokenExchange)})
}

// IsManagedAIGatewayAudience reports whether the credential-free AI audience
// is owned by Tikti's tenant AI identity contract and currently ACTIVE. Only an
// active managed record opens AI user exchange; unmanaged look-alikes fail.
func IsManagedAIGatewayAudience(tenantID string, client *Client) bool {
	return IsManagedAIGatewayAudienceRecord(tenantID, client) && client.Status == ClientStatusActive
}

// IsManagedAIGatewayAudienceRecord accepts the managed AI audience in either
// lifecycle state. INACTIVE records are retained while the tenant feature is
// disabled and are reactivated, never recreated, when it is enabled again.
func IsManagedAIGatewayAudienceRecord(tenantID string, client *Client) bool {
	return client != nil && client.Id == AIGatewayAudienceClientID && client.TenantId == tenantID &&
		client.SecretHash == "" && client.Type == ClientTypeService &&
		(client.Status == ClientStatusActive || client.Status == ClientStatusInactive) &&
		client.ManagedBy == AIGatewayAudienceClientManager &&
		slices.Equal(client.AllowedGrantTypes, []string{string(GrantTypeTokenExchange)})
}

// AIGatewayIdentityResp is the credential-free projection of a tenant's
// managed AI audience and its dedicated roles.
type AIGatewayIdentityResp struct {
	TenantId string                    `json:"tenantId"`
	Client   ManagedAudienceClientResp `json:"client"`
	Roles    []RoleResp                `json:"roles"`
	// AdminAssignment is the only assignment activation performs: the
	// tenant AI admin role for the enabling administrator's own user.
	AdminAssignment AIGatewayAdminAssignmentResp `json:"adminAssignment"`
}

// AIGatewayAdminAssignmentResp names the enabling administrator and the one
// role activation guarantees for that user in the tenant.
type AIGatewayAdminAssignmentResp struct {
	PrincipalId string `json:"principalId"`
	Role        string `json:"role"`
}

// AIGatewayDeactivationResp reports the managed AI audience after disabling.
// Status is INACTIVE, or ABSENT when the tenant never had the audience.
type AIGatewayDeactivationResp struct {
	TenantId string `json:"tenantId"`
	ClientId string `json:"clientId"`
	Status   string `json:"status"`
}

// AIGatewayClientAbsent reports that no managed AI audience exists.
const AIGatewayClientAbsent = "ABSENT"
