package nativepolicy

import "slices"

// Registry is immutable after construction. Foreign SAML application access is
// derived only from explicitly registered authentication/target tenant pairs.
type Registry struct {
	clients      map[string]Client
	foreignRoles map[string]map[string]bool
	roleScopes   map[string][]string
}

func NewRegistry(clients []Client) (*Registry, error) {
	if len(clients) > MaximumClients {
		return nil, ErrInvalidClient
	}
	r := &Registry{clients: map[string]Client{}, foreignRoles: map[string]map[string]bool{}, roleScopes: map[string][]string{}}
	for _, input := range clients {
		client, err := input.Normalize()
		if err != nil {
			return nil, err
		}
		if _, exists := r.clients[client.ID]; exists {
			return nil, ErrInvalidClient
		}
		r.clients[client.ID] = client
		for _, role := range append([]Role{client.BaseRole}, client.AdditionalRoles...) {
			roleKey := client.TenantID + "\x00" + role.Name
			if scopes, exists := r.roleScopes[roleKey]; exists && !slices.Equal(scopes, role.Scopes) {
				return nil, ErrInvalidClient
			}
			r.roleScopes[roleKey] = slices.Clone(role.Scopes)
			if client.IdentityTenantID != client.TenantID {
				key := client.IdentityTenantID + "\x00" + client.TenantID
				if r.foreignRoles[key] == nil {
					r.foreignRoles[key] = map[string]bool{}
				}
				r.foreignRoles[key][role.Name] = true
			}
		}
	}
	return r, nil
}

func (r *Registry) Get(id string) (Client, bool) {
	if r == nil {
		return Client{}, false
	}
	client, exists := r.clients[id]
	if !exists {
		return Client{}, false
	}
	copy, err := client.Normalize()
	return copy, err == nil
}

func (r *Registry) AllowsForeignRole(sourceTenant, targetTenant, role string) bool {
	return r != nil && r.foreignRoles[sourceTenant+"\x00"+targetTenant][role]
}

func (r *Registry) HasForeignTrust(sourceTenant, targetTenant string) bool {
	return r != nil && len(r.foreignRoles[sourceTenant+"\x00"+targetTenant]) > 0
}

func (r *Registry) AllowsForeignAssignment(sourceTenant, targetTenant string, roles []string) bool {
	if len(roles) == 0 || len(roles) > 100 {
		return false
	}
	for _, role := range roles {
		if !r.AllowsForeignRole(sourceTenant, targetTenant, role) {
			return false
		}
	}
	return true
}

func (r *Registry) ExpectedRoleScopes(tenantID, role string) ([]string, bool) {
	if r == nil {
		return nil, false
	}
	scopes, exists := r.roleScopes[tenantID+"\x00"+role]
	return slices.Clone(scopes), exists
}
