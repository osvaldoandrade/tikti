package domain

// ClientStatus controls whether a registered client may participate in token
// issuance. Exact administrative reads return inactive clients as inventory.
type ClientStatus string

const (
	ClientStatusActive   ClientStatus = "ACTIVE"
	ClientStatusInactive ClientStatus = "INACTIVE"
)

// ClientIdentity is the credential-free projection returned by exact client
// reads. Client secrets and their hashes deliberately have no representation.
type ClientIdentity struct {
	ClientId          string       `json:"clientId"`
	TenantId          string       `json:"tenantId"`
	Type              ClientType   `json:"type"`
	AllowedGrantTypes []string     `json:"allowedGrantTypes"`
	DefaultScopes     []string     `json:"defaultScopes"`
	Status            ClientStatus `json:"status"`
}
