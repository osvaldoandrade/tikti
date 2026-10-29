// Package nativepolicy defines the server-owned authority of a public native
// client. Browser requests select a registered client; they never define its
// tenant, audience, authentication realm or permission ceiling.
package nativepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

var (
	ErrInvalidClient = errors.New("invalid native client policy")
	ErrAccessDenied  = errors.New("native client access denied")
	identifier       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	roleName         = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`)
	scopeName        = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
)

const MaximumClients = 128

func ValidScope(value string) bool { return scopeName.MatchString(value) }

type Role struct {
	Name   string   `json:"name" yaml:"name"`
	Scopes []string `json:"scopes" yaml:"scopes"`
}

type Client struct {
	ID               string   `json:"id" yaml:"id"`
	Name             string   `json:"name" yaml:"name"`
	TenantID         string   `json:"tenantId" yaml:"tenantId"`
	IdentityTenantID string   `json:"identityTenantId" yaml:"identityTenantId"`
	Audience         string   `json:"audience" yaml:"audience"`
	RedirectPath     string   `json:"redirectPath" yaml:"redirectPath"`
	BaseRole         Role     `json:"baseRole" yaml:"baseRole"`
	AdditionalRoles  []Role   `json:"additionalRoles" yaml:"additionalRoles"`
	RequiredScopes   []string `json:"requiredScopes" yaml:"requiredScopes"`
	TTLSeconds       int      `json:"ttlSeconds" yaml:"ttlSeconds"`
}

func validScopes(values []string) bool {
	if len(values) == 0 || len(values) > 128 {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if !scopeName.MatchString(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func validPath(value string) bool {
	if value == "" || len(value) > 256 || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
		strings.ContainsAny(value, "\\?#%") || path.Clean(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

// Normalize validates and returns a detached, deterministic copy. Callers cannot
// mutate the policy after a registry accepts it through a shared slice.
func (c Client) Normalize() (Client, error) {
	if !identifier.MatchString(c.ID) || !identifier.MatchString(c.TenantID) || !identifier.MatchString(c.IdentityTenantID) ||
		!identifier.MatchString(c.Audience) || !validPath(c.RedirectPath) || c.TTLSeconds < 60 || c.TTLSeconds > 3600 ||
		len(c.Name) < 1 || len(c.Name) > 100 || strings.TrimSpace(c.Name) != c.Name || len(c.AdditionalRoles) > 31 ||
		!validScopes(c.RequiredScopes) {
		return Client{}, ErrInvalidClient
	}
	for _, character := range c.Name {
		if unicode.IsControl(character) {
			return Client{}, ErrInvalidClient
		}
	}
	roles := append([]Role{c.BaseRole}, c.AdditionalRoles...)
	seenRoles := make(map[string]bool, len(roles))
	ceiling := make(map[string]bool)
	for index, role := range roles {
		if !roleName.MatchString(role.Name) || !validScopes(role.Scopes) || seenRoles[role.Name] {
			return Client{}, ErrInvalidClient
		}
		seenRoles[role.Name] = true
		roles[index].Scopes = slices.Clone(role.Scopes)
		slices.Sort(roles[index].Scopes)
		for _, scope := range role.Scopes {
			ceiling[scope] = true
		}
	}
	if len(ceiling) > 500 {
		return Client{}, ErrInvalidClient
	}
	for _, required := range c.RequiredScopes {
		if !ceiling[required] {
			return Client{}, ErrInvalidClient
		}
	}
	c.BaseRole = roles[0]
	c.AdditionalRoles = roles[1:]
	slices.SortFunc(c.AdditionalRoles, func(a, b Role) int { return strings.Compare(a.Name, b.Name) })
	c.RequiredScopes = slices.Clone(c.RequiredScopes)
	slices.Sort(c.RequiredScopes)
	return c, nil
}

func (c Client) Fingerprint() (string, error) {
	normalized, err := c.Normalize()
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", ErrInvalidClient
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// ValidateRedirect allows the native application's ephemeral loopback port,
// while preserving an exact registered path and literal IPv4/IPv6 loopback host.
func (c Client) ValidateRedirect(raw string) error {
	if !validPath(c.RedirectPath) || len(raw) > 1024 {
		return ErrInvalidClient
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "http" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" ||
		u.Path != c.RedirectPath || u.String() != raw {
		return ErrInvalidClient
	}
	if host := u.Hostname(); host != "127.0.0.1" && host != "::1" {
		return ErrInvalidClient
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != u.Port() {
		return ErrInvalidClient
	}
	return nil
}

// ScopesForRoles computes the exact configured union from explicit target
// assignments. Global ADMIN metadata and unknown roles grant nothing here.
func (c Client) ScopesForRoles(assigned []string) ([]string, error) {
	normalized, err := c.Normalize()
	if err != nil {
		return nil, err
	}
	held := make(map[string]bool, len(assigned))
	for _, role := range assigned {
		held[role] = true
	}
	if !held[normalized.BaseRole.Name] {
		return nil, ErrAccessDenied
	}
	set := make(map[string]bool)
	for _, role := range append([]Role{normalized.BaseRole}, normalized.AdditionalRoles...) {
		if held[role.Name] {
			for _, scope := range role.Scopes {
				set[scope] = true
			}
		}
	}
	for _, required := range normalized.RequiredScopes {
		if !set[required] {
			return nil, ErrAccessDenied
		}
	}
	scopes := make([]string, 0, len(set))
	for scope := range set {
		scopes = append(scopes, scope)
	}
	slices.Sort(scopes)
	return scopes, nil
}
