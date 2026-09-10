package config

import (
	"fmt"
	"strings"
)

// ValidateTenantRuntimeAuthority binds the independent machine read to the
// existing private key. SQL admission and browser identity flags are unrelated.
func (c *Config) ValidateTenantRuntimeAuthority() error {
	if c == nil {
		return fmt.Errorf("configuration is required")
	}
	if !c.TenantRuntimeAuthorityV1 {
		return nil
	}
	if len(c.ApiKey) == 0 || len(c.ApiKey) > 4096 || strings.TrimSpace(c.ApiKey) != c.ApiKey ||
		strings.ContainsAny(c.ApiKey, ",\r\n") || strings.Contains(c.ApiKey, "${") {
		return fmt.Errorf("tenant runtime authority requires a resolved private API key")
	}
	for _, character := range c.ApiKey {
		if character < 32 || character == 127 {
			return fmt.Errorf("tenant runtime authority requires a resolved private API key")
		}
	}
	return nil
}
