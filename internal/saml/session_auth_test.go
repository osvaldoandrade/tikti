package saml

import (
	"context"
	"errors"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// fakeRepo implements the subset of repository.UserRepository used by
// sessionBridgeAuth.
type fakeRepo struct {
	user      domain.User
	created   bool
	err       error
	roles     []string
	updated   *domain.User
	updateErr error
}

func (f *fakeRepo) CreateUser(context.Context, *domain.User) error { return nil }
func (f *fakeRepo) FindByEmail(context.Context, string) (*domain.User, error) {
	return nil, nil
}
func (f *fakeRepo) UpdateUser(_ context.Context, user *domain.User) error {
	copy := *user
	f.updated = &copy
	return f.updateErr
}
func (f *fakeRepo) DeleteByEmail(context.Context, string) error { return nil }
func (f *fakeRepo) GetAllUsers(context.Context) ([]*domain.User, error) {
	return nil, nil
}
func (f *fakeRepo) SetStatus(context.Context, string, domain.UserStatus) (*domain.User, error) {
	return nil, nil
}
func (f *fakeRepo) IncrementTokenVersion(context.Context, string) (int, *domain.User, error) {
	return 0, nil, nil
}
func (f *fakeRepo) SaveOobCode(context.Context, string, string, string) error { return nil }
func (f *fakeRepo) ConsumeOobCode(context.Context, string, string) (string, error) {
	return "", nil
}
func (f *fakeRepo) UpsertFromSAML(_ context.Context, _, _, _, _ string, roles []string, _ domain.MergeStrategy) (domain.User, bool, error) {
	f.roles = append([]string(nil), roles...)
	return f.user, f.created, f.err
}

// fakeIssuer captures the arguments passed to IssueIDTokenWithAMR.
type fakeIssuer struct {
	token                 string
	lastAMR               []string
	lastUser              domain.User
	lastPlatformPrivilege string
	err                   error
}

func (f *fakeIssuer) IssueIDTokenWithAMR(u *domain.User, amr []string, platformPrivilege string) (string, int, error) {
	f.lastAMR = amr
	f.lastUser = *u
	f.lastPlatformPrivilege = platformPrivilege
	return f.token, 3600, f.err
}

func TestSessionBridge_Issue_DowngradesTenantSAMLPlatformAdmin(t *testing.T) {
	repo := &fakeRepo{user: domain.User{Id: "u1", Email: "admin@example.com", Role: domain.RoleAdmin, AuthSource: domain.AuthSourceSAML}}
	issuer := &fakeIssuer{token: "tenant-token"}
	bridge := NewSessionBridge(repo, issuer)
	_, err := bridge.Issue(context.Background(), IssueInput{
		TenantID: "tenant-1", ExternalSubject: "external-admin", Email: "admin@example.com",
		Roles: []string{"ADMIN"}, AMR: []string{"saml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if issuer.lastUser.Role != domain.RoleCompanyAdmin || issuer.lastUser.CompanyId == nil || *issuer.lastUser.CompanyId != "tenant-1" {
		t.Fatalf("unsafe SAML issuer user: %#v", issuer.lastUser)
	}
	if issuer.lastPlatformPrivilege != "" {
		t.Fatalf("tenant SAML administrator received platform provenance: %q", issuer.lastPlatformPrivilege)
	}
}

func TestSessionBridge_Issue_ElevatesOnlyConfiguredSAMLPlatformAdministrator(t *testing.T) {
	tenantID := "local-tenant"
	repo := &fakeRepo{user: domain.User{
		Id: "u1", Email: "owner@example.com", Role: domain.RoleCompanyAdmin,
		AuthSource: domain.AuthSourceSAML, CompanyId: &tenantID,
	}}
	issuer := &fakeIssuer{token: "platform-token"}
	bridge := NewSessionBridge(repo, issuer, WithPlatformAdministrators([]config.SAMLPlatformAdministrator{
		{TenantID: tenantID, Email: "owner@example.com"},
	}))

	_, err := bridge.Issue(context.Background(), IssueInput{
		TenantID: tenantID, ExternalSubject: "external-owner", Email: "Owner@Example.com",
		AMR: []string{"saml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if issuer.lastUser.Role != domain.RoleAdmin || repo.updated == nil || repo.updated.Role != domain.RoleAdmin {
		t.Fatalf("configured platform administrator was not persisted and issued as ADMIN: issued=%#v updated=%#v", issuer.lastUser, repo.updated)
	}
	if issuer.lastPlatformPrivilege != domain.PlatformPrivilegeAdmin {
		t.Fatalf("configured platform administrator provenance = %q", issuer.lastPlatformPrivilege)
	}
}

func TestSessionBridge_Issue_DoesNotElevatePlatformAdministratorAcrossTenant(t *testing.T) {
	repo := &fakeRepo{user: domain.User{
		Id: "u1", Email: "owner@example.com", Role: domain.RoleCompanyAdmin,
		AuthSource: domain.AuthSourceSAML,
	}}
	issuer := &fakeIssuer{token: "tenant-token"}
	bridge := NewSessionBridge(repo, issuer, WithPlatformAdministrators([]config.SAMLPlatformAdministrator{
		{TenantID: "local-tenant", Email: "owner@example.com"},
	}))

	_, err := bridge.Issue(context.Background(), IssueInput{
		TenantID: "foreign-tenant", ExternalSubject: "external-owner", Email: "owner@example.com",
		AMR: []string{"saml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if issuer.lastUser.Role != domain.RoleCompanyAdmin || repo.updated != nil {
		t.Fatalf("platform administrator escaped configured tenant: issued=%#v updated=%#v", issuer.lastUser, repo.updated)
	}
	if issuer.lastPlatformPrivilege != "" {
		t.Fatalf("cross-tenant platform provenance = %q", issuer.lastPlatformPrivilege)
	}
}

func TestSessionBridge_Issue_FailsClosedWhenPlatformAdministratorCannotPersist(t *testing.T) {
	repoErr := errors.New("write unavailable")
	repo := &fakeRepo{
		user:      domain.User{Id: "u1", Email: "owner@example.com", Role: domain.RoleCompanyAdmin, AuthSource: domain.AuthSourceSAML},
		updateErr: repoErr,
	}
	issuer := &fakeIssuer{token: "must-not-issue"}
	bridge := NewSessionBridge(repo, issuer, WithPlatformAdministrators([]config.SAMLPlatformAdministrator{
		{TenantID: "local-tenant", Email: "owner@example.com"},
	}))

	_, err := bridge.Issue(context.Background(), IssueInput{
		TenantID: "local-tenant", ExternalSubject: "external-owner", Email: "owner@example.com",
		AMR: []string{"saml"},
	})
	if !errors.Is(err, repoErr) {
		t.Fatalf("expected persistence error, got %v", err)
	}
	if issuer.lastUser.Id != "" {
		t.Fatalf("token issued after privilege persistence failure: %#v", issuer.lastUser)
	}
}

func TestSessionBridge_Issue_SAML(t *testing.T) {
	repo := &fakeRepo{
		user: domain.User{Id: "u1", Email: "alice@example.com", Role: domain.RoleCompanyEmployee},
	}
	issuer := &fakeIssuer{token: "tok-saml"}
	bridge := NewSessionBridge(repo, issuer)

	tok, err := bridge.Issue(context.Background(), IssueInput{
		TenantID:        "tenant-1",
		ExternalSubject: "ext-sub-1",
		Email:           "alice@example.com",
		Name:            "Alice",
		AMR:             []string{"saml"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "tok-saml" {
		t.Fatalf("expected tok-saml, got %q", tok)
	}
	if len(issuer.lastAMR) != 1 || issuer.lastAMR[0] != "saml" {
		t.Fatalf("expected amr=[saml], got %v", issuer.lastAMR)
	}
}

func TestSessionBridge_Issue_UpsertError(t *testing.T) {
	repo := &fakeRepo{err: errors.New("db down")}
	issuer := &fakeIssuer{token: "should-not-reach"}
	bridge := NewSessionBridge(repo, issuer)

	_, err := bridge.Issue(context.Background(), IssueInput{
		TenantID:        "tenant-1",
		ExternalSubject: "ext-sub-1",
		Email:           "alice@example.com",
		AMR:             []string{"saml"},
	})
	if err == nil {
		t.Fatal("expected error from upsert failure")
	}
	if !errors.Is(err, repo.err) {
		t.Fatalf("expected wrapped db error, got %v", err)
	}
}
