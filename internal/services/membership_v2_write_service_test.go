package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type membershipV2WriteFixture struct {
	tenant       *domain.Tenant
	tenantErr    error
	user         *domain.UserIdentity
	userErr      error
	roles        []*domain.Role
	rolesErr     error
	ensureErr    error
	ensureCalls  int
	ensureCreate bool
	projection   *domain.Membership
}

type membershipV2WriteTenants struct{ *membershipV2WriteFixture }
type membershipV2WriteUsers struct{ *membershipV2WriteFixture }
type membershipV2WriteRoles struct{ *membershipV2WriteFixture }
type membershipV2WriteRepo struct{ *membershipV2WriteFixture }

func (f membershipV2WriteTenants) GetExact(context.Context, string) (*domain.Tenant, error) {
	return f.tenant, f.tenantErr
}
func (f membershipV2WriteUsers) GetExact(context.Context, string) (*domain.UserIdentity, error) {
	return f.user, f.userErr
}
func (f membershipV2WriteRoles) GetManyExact(context.Context, string, []string) ([]*domain.Role, error) {
	return f.roles, f.rolesErr
}
func (f membershipV2WriteRepo) Ensure(_ context.Context, tenantID, userID string, roles []string) (*domain.Membership, bool, error) {
	f.ensureCalls++
	if f.ensureErr != nil {
		return nil, false, f.ensureErr
	}
	if f.projection != nil {
		return f.projection, f.ensureCreate, nil
	}
	return &domain.Membership{Id: repository.ExpectedMembershipV2ID(tenantID, userID), TenantId: tenantID, UserId: userID, Roles: roles, CreatedAt: time.Now()}, f.ensureCreate, nil
}
func (f membershipV2WriteRepo) GetExact(context.Context, string, string) (*domain.Membership, error) {
	return nil, nil
}

func validMembershipV2WriteFixture() *membershipV2WriteFixture {
	return &membershipV2WriteFixture{
		tenant: &domain.Tenant{Id: "bereia", Status: domain.TenantStatusActive},
		user:   &domain.UserIdentity{Id: "user-1", Status: domain.UserStatusActive},
		roles: []*domain.Role{{Name: "reader", Scope: domain.RoleScopeTenant, TenantId: "bereia",
			Permissions: []string{"content:read"}}}, ensureCreate: true,
	}
}

func TestMembershipV2WriteServiceContract(t *testing.T) {
	roles := []string{"reader"}
	for _, test := range []struct {
		name    string
		mutate  func(*membershipV2WriteFixture)
		want    error
		calls   int
		created bool
	}{
		{"create", func(*membershipV2WriteFixture) {}, nil, 1, true},
		{"replay", func(f *membershipV2WriteFixture) { f.ensureCreate = false }, nil, 1, false},
		{"missing tenant", func(f *membershipV2WriteFixture) { f.tenant = nil }, domain.ErrMembershipDependencyNotFound, 0, false},
		{"disabled tenant", func(f *membershipV2WriteFixture) { f.tenant.Status = domain.TenantStatusDisabled }, domain.ErrMembershipDependencyInactive, 0, false},
		{"tenant corruption", func(f *membershipV2WriteFixture) { f.tenant.Id = "other" }, errMembershipV2WriteUnavailable, 0, false},
		{"tenant canceled", func(f *membershipV2WriteFixture) { f.tenantErr = context.DeadlineExceeded }, context.DeadlineExceeded, 0, false},
		{"missing user", func(f *membershipV2WriteFixture) { f.user = nil }, domain.ErrMembershipDependencyNotFound, 0, false},
		{"suspended user", func(f *membershipV2WriteFixture) { f.user.Status = domain.UserStatusSuspended }, domain.ErrMembershipDependencyInactive, 0, false},
		{"user corruption", func(f *membershipV2WriteFixture) { f.user.Status = "BROKEN" }, errMembershipV2WriteUnavailable, 0, false},
		{"user storage", func(f *membershipV2WriteFixture) { f.userErr = errors.New("secret") }, errMembershipV2WriteUnavailable, 0, false},
		{"missing role", func(f *membershipV2WriteFixture) { f.roles[0] = nil }, domain.ErrMembershipDependencyNotFound, 0, false},
		{"role cardinality", func(f *membershipV2WriteFixture) { f.roles = nil }, errMembershipV2WriteUnavailable, 0, false},
		{"wrong role", func(f *membershipV2WriteFixture) { f.roles[0].TenantId = "other" }, errMembershipV2WriteUnavailable, 0, false},
		{"role storage", func(f *membershipV2WriteFixture) { f.rolesErr = errors.New("secret") }, errMembershipV2WriteUnavailable, 0, false},
		{"repository conflict", func(f *membershipV2WriteFixture) { f.ensureErr = domain.ErrMembershipConflict }, domain.ErrMembershipConflict, 1, false},
		{"repository storage", func(f *membershipV2WriteFixture) { f.ensureErr = errors.New("secret") }, errMembershipV2WriteUnavailable, 1, false},
		{"invalid projection", func(f *membershipV2WriteFixture) { f.projection = &domain.Membership{} }, errMembershipV2WriteUnavailable, 1, false},
		{"foreign projection ID", func(f *membershipV2WriteFixture) {
			f.projection = &domain.Membership{Id: "foreign-id-canary", TenantId: "bereia", UserId: "user-1", Roles: roles, CreatedAt: time.Now()}
		}, errMembershipV2WriteUnavailable, 1, false},
		{"canceled", func(f *membershipV2WriteFixture) { f.ensureErr = context.Canceled }, context.Canceled, 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := validMembershipV2WriteFixture()
			test.mutate(fixture)
			svc := NewMembershipV2WriteService(membershipV2WriteTenants{fixture}, membershipV2WriteUsers{fixture}, membershipV2WriteRoles{fixture}, membershipV2WriteRepo{fixture})
			result, created, err := svc.Ensure(context.Background(), "bereia", "user-1", roles)
			if !errors.Is(err, test.want) || fixture.ensureCalls != test.calls || (test.want == nil && (result == nil || created != test.created)) {
				t.Fatalf("Ensure() = %#v, %v, calls=%d", result, err, fixture.ensureCalls)
			}
		})
	}
	fixture := validMembershipV2WriteFixture()
	svc := NewMembershipV2WriteService(membershipV2WriteTenants{fixture}, membershipV2WriteUsers{fixture}, membershipV2WriteRoles{fixture}, membershipV2WriteRepo{fixture})
	if _, _, err := NewMembershipV2WriteService(nil, nil, nil, nil).Ensure(context.Background(), "bereia", "user-1", roles); !errors.Is(err, errMembershipV2WriteUnavailable) {
		t.Fatalf("nil dependencies = %v", err)
	}
	for _, input := range []struct {
		tenant, user string
		roles        []string
	}{{"Bereia", "user-1", roles}, {"bereia", "..", roles}, {"bereia", "bad/user", roles}, {"bereia", "user-1", nil}, {"bereia", "user-1", make([]string, 101)}, {"bereia", "user-1", []string{"writer", "reader"}}} {
		if _, _, err := svc.Ensure(context.Background(), input.tenant, input.user, input.roles); err == nil || fixture.ensureCalls != 0 {
			t.Fatalf("invalid input accepted: %#v", input)
		}
	}
}
