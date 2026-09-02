package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestTenantScopedTokenClaimsIsolateBereia(t *testing.T) {
	company := "storifly"
	user := &domain.User{Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive, Role: domain.RoleAdmin, CompanyId: &company, TokenVersion: 4}
	users := &mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return user, nil }}
	memberships := &mockMembershipRepo{
		listTenantIDsByUser: func(context.Context, string) ([]string, error) {
			t.Fatal("protected alias reached legacy membership path")
			return nil, nil
		},
		listExactFn: func(context.Context, string) ([]string, error) { return []string{"bereia", "storifly"}, nil },
		getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
			roles := map[string][]string{"bereia": {"bereia-read"}, "storifly": {"storifly-admin"}}
			return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: roles[tenantID]}, nil
		},
	}
	roleCalls := 0
	roles := &mockRoleService{getByNameFn: func(_ context.Context, tenantID, roleName string) (*domain.RoleResp, error) {
		roleCalls++
		if tenantID != "bereia" || roleName != "bereia-read" {
			t.Fatalf("cross-tenant role read: tenant=%q role=%q", tenantID, roleName)
		}
		return &domain.RoleResp{Name: roleName, Permissions: []string{"bereia:read", "bereia:write"}}, nil
	}}
	tenants := &fakeTenantRepo{getFn: func(context.Context, string) (*domain.Tenant, error) {
		return &domain.Tenant{Id: "bereia", Status: domain.TenantStatusActive}, nil
	}}
	svc := NewUserService(users, memberships, roles, nil, "secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithTenantScopedTokenClaimsV1(true, []string{"bereia"}, tenants)).(*userService)
	idToken := signIDToken(t, "secret", user.Email)
	for _, alias := range []string{" bereia ", "Bereia", " BEREIA ", "beReIa", "\tBeReIa\n"} {
		if response, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idToken, Audience: "bereia-api", TenantID: alias, Scopes: []string{"storifly:admin"}}); err != domain.ErrInvalidTenant || response != nil {
			t.Fatalf("protected tenant alias %q bypassed strict path: response=%+v err=%v", alias, response, err)
		}
	}
	originalList := memberships.listExactFn
	memberships.listExactFn = func(context.Context, string) ([]string, error) { return nil, errors.New("redis unavailable") }
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idToken, Audience: "bereia-api", TenantID: "bereia"}); err != domain.ErrInvalidTenant {
		t.Fatalf("strict storage failure was not closed: %v", err)
	}
	memberships.listExactFn = originalList
	originalUser := users.findByEmailFn
	users.findByEmailFn = func(context.Context, string) (*domain.User, error) { return nil, errors.New("redis unavailable") }
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idToken, Audience: "bereia-api", TenantID: "bereia"}); err != domain.ErrInvalidToken {
		t.Fatalf("strict user storage failure was not closed: %v", err)
	}
	users.findByEmailFn = originalUser
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idToken, Audience: "bereia-api", TenantID: "bereia", Scopes: []string{"storifly:admin"}}); err != domain.ErrUnauthorizedScope {
		t.Fatalf("global ADMIN leaked Storifly scope: %v", err)
	}
	svc.clientSvc = &mockClientService{getClientFn: func(context.Context, string, string) (*domain.Client, error) {
		return &domain.Client{Id: "bereia-api", Status: "ACTIVE", DefaultScopes: []string{"storifly:admin"}}, nil
	}}
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idToken, Audience: "bereia-api", TenantID: "bereia"}); err != domain.ErrUnauthorizedScope {
		t.Fatalf("foreign client default leaked into Bereia: %v", err)
	}
	svc.clientSvc = nil
	resp, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idToken, Audience: "bereia-api", TenantID: "bereia", Scopes: []string{"bereia:write", "bereia:read", "bereia:read"}})
	if err != nil {
		t.Fatalf("strict exchange: %v", err)
	}
	key, _ := svc.getRSAPrivateKey()
	claims, err := utils.ValidateRS256(resp.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", "bereia-api")
	if err != nil || claims["tid"] != "bereia" || claims["scope"] != "bereia:read bereia:write" || claims["role"] != nil ||
		!reflect.DeepEqual(claims["roles"], []interface{}{"bereia-read"}) || strings.Contains(resp.AccessToken, "storifly-admin") || roleCalls != 3 {
		t.Fatalf("non-isolated claims=%v err=%v roleCalls=%d", claims, err, roleCalls)
	}
}

func TestTenantScopedTokenClaimsPreserveLegacyOutsideCanary(t *testing.T) {
	for _, test := range []struct {
		name, target, want string
		enabled            bool
	}{
		{name: "Storifly outside allowlist", target: "Storifly", want: "Storifly", enabled: true},
		{name: "Code Company omitted", want: "code-company", enabled: true},
		{name: "Bereia flag off", target: "bereia", want: "bereia"},
		{name: "Bereia alias flag off", target: " BEREIA ", want: "BEREIA"},
	} {
		t.Run(test.name, func(t *testing.T) {
			user := &domain.User{Id: "user-1", Email: "admin@example.com", Status: domain.UserStatusActive, Role: domain.RoleAdmin}
			memberships := &mockMembershipRepo{listTenantIDsByUser: func(context.Context, string) ([]string, error) {
				if test.target == "" {
					return []string{"storifly", "code-company"}, nil
				}
				return []string{test.want}, nil
			}, listExactFn: func(context.Context, string) ([]string, error) {
				t.Fatal("strict reverse read on legacy path")
				return nil, nil
			}}
			svc := NewUserService(&mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return user, nil }}, memberships, nil, nil,
				"secret", "https://issuer", "tikti", makePEMKey(t), "kid", WithTenantScopedTokenClaimsV1(test.enabled, []string{"bereia"}, &fakeTenantRepo{})).(*userService)
			resp, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: signIDToken(t, "secret", user.Email), Audience: "legacy-api", TenantID: test.target, Scopes: []string{"legacy:admin"}})
			if err != nil {
				t.Fatalf("legacy exchange: %v", err)
			}
			key, _ := svc.getRSAPrivateKey()
			claims, err := utils.ValidateRS256(resp.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", "legacy-api")
			if err != nil || claims["tid"] != test.want || claims["role"] != "ADMIN" || claims["roles"] != nil || claims["scope"] != "legacy:admin" {
				t.Fatalf("legacy claims=%v err=%v", claims, err)
			}
		})
	}
}

func TestTenantScopedTokenV1PreservesFiveHundredRoleMembershipCompatibility(t *testing.T) {
	roleNames := make([]string, 500)
	for index := range roleNames {
		roleNames[index] = fmt.Sprintf("role-%03d", index)
	}
	roleReads := 0
	memberships := &mockMembershipRepo{
		listExactFn: func(context.Context, string) ([]string, error) { return []string{"bereia"}, nil },
		getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
			return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: append([]string(nil), roleNames...)}, nil
		},
	}
	service := NewUserService(
		nil,
		memberships,
		&mockRoleService{getByNameFn: func(_ context.Context, _ string, roleName string) (*domain.RoleResp, error) {
			roleReads++
			return &domain.RoleResp{Name: roleName, Permissions: []string{"bereia:read"}}, nil
		}},
		nil, "", "", "", "", "",
		WithTenantScopedTokenClaimsV1(true, []string{"bereia"}, &fakeTenantRepo{getFn: func(context.Context, string) (*domain.Tenant, error) {
			return &domain.Tenant{Id: "bereia", Status: domain.TenantStatusActive}, nil
		}}),
	).(*userService)
	authorization, err := service.resolveTenantScopedTokenAuthorization(
		context.Background(), &domain.User{Id: "user-1", Status: domain.UserStatusActive}, "bereia",
	)
	if err != nil || len(authorization.roles) != 500 || roleReads != 500 {
		t.Fatalf("v1 compatibility roles=%d reads=%d err=%v", len(authorization.roles), roleReads, err)
	}
}

func TestTenantScopedTokenAuthorizationFailsClosed(t *testing.T) {
	failure := errors.New("storage failure")
	for _, test := range []struct {
		name, fault string
	}{
		{name: "inactive user", fault: "user"}, {name: "reverse error", fault: "list-error"},
		{name: "target absent", fault: "target-absent"}, {name: "membership read error", fault: "get-error"},
		{name: "reverse dangling", fault: "dangling"},
		{name: "membership mismatch", fault: "membership"}, {name: "duplicate roles", fault: "roles"},
		{name: "membership role limit", fault: "roles-limit"},
		{name: "tenant error", fault: "tenant-error"}, {name: "tenant missing", fault: "tenant-missing"},
		{name: "tenant disabled", fault: "tenant-disabled"},
		{name: "role service missing", fault: "role-service"}, {name: "role error", fault: "role-error"},
		{name: "role missing", fault: "role-missing"}, {name: "role mismatch", fault: "role"},
		{name: "permission corrupt", fault: "permission"}, {name: "reserved permission", fault: "policy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			user := &domain.User{Id: "user-1", Status: domain.UserStatusActive}
			if test.fault == "user" {
				user.Status = domain.UserStatusInactive
			}
			memberships := &mockMembershipRepo{
				listExactFn: func(context.Context, string) ([]string, error) {
					if test.fault == "list-error" {
						return nil, failure
					}
					if test.fault == "target-absent" {
						return []string{"storifly"}, nil
					}
					if test.fault == "dangling" {
						return []string{"bereia", "storifly"}, nil
					}
					return []string{"bereia"}, nil
				},
				getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
					if test.fault == "get-error" {
						return nil, failure
					}
					if test.fault == "dangling" && tenantID == "storifly" {
						return nil, nil
					}
					if test.fault == "membership" {
						tenantID = "storifly"
					}
					roles := []string{"bereia-read"}
					if test.fault == "roles" {
						roles = append(roles, roles[0])
					}
					if test.fault == "roles-limit" {
						roles = make([]string, 501)
					}
					return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: roles}, nil
				},
			}
			tenants := &fakeTenantRepo{getFn: func(context.Context, string) (*domain.Tenant, error) {
				if test.fault == "tenant-error" {
					return nil, failure
				}
				if test.fault == "tenant-missing" {
					return nil, nil
				}
				status := domain.TenantStatusActive
				if test.fault == "tenant-disabled" {
					status = domain.TenantStatusDisabled
				}
				return &domain.Tenant{Id: "bereia", Status: status}, nil
			}}
			roles := &mockRoleService{getByNameFn: func(context.Context, string, string) (*domain.RoleResp, error) {
				if test.fault == "role-error" {
					return nil, failure
				}
				if test.fault == "role-missing" {
					return nil, nil
				}
				name := "bereia-read"
				if test.fault == "role" {
					name = "storifly-admin"
				}
				permissions := []string{"bereia:read"}
				if test.fault == "permission" {
					permissions = append(permissions, permissions[0])
				}
				if test.fault == "policy" {
					permissions = []string{"code-admin:tenants:admin"}
				}
				return &domain.RoleResp{Name: name, Permissions: permissions}, nil
			}}
			svc := NewUserService(nil, memberships, roles, nil, "", "", "", "", "", WithTenantScopedTokenClaimsV1(true, []string{"bereia"}, tenants)).(*userService)
			if test.fault == "role-service" {
				svc.roleSvc = nil
			}
			if authorization, err := svc.resolveTenantScopedTokenAuthorization(context.Background(), user, "bereia"); err == nil || len(authorization.roles) != 0 || len(authorization.permissions) != 0 {
				t.Fatalf("fault %q authorized: %+v err=%v", test.fault, authorization, err)
			}
		})
	}
}

func FuzzCanonicalMembershipRoles(f *testing.F) {
	for _, seed := range []string{"bereia-read", "storifly-admin,bereia-read", "../admin", "read,read", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		input := strings.Split(encoded, ",")
		before := append([]string(nil), input...)
		roles, ok := canonicalMembershipRoles(input)
		if !reflect.DeepEqual(input, before) {
			t.Fatal("validator mutated stored roles")
		}
		if ok {
			for index, role := range roles {
				if !validRoleName(role) || index > 0 && roles[index-1] >= role {
					t.Fatalf("non-canonical roles: %q", roles)
				}
			}
		}
	})
}
