package saml

import (
	"context"
	"errors"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// fakeRepo implements the subset of repository.UserRepository used by
// sessionBridgeAuth.
type fakeRepo struct {
	user    domain.User
	created bool
	err     error
}

func (f *fakeRepo) CreateUser(context.Context, *domain.User) error { return nil }
func (f *fakeRepo) FindByEmail(context.Context, string) (*domain.User, error) {
	return nil, nil
}
func (f *fakeRepo) UpdateUser(context.Context, *domain.User) error  { return nil }
func (f *fakeRepo) DeleteByEmail(context.Context, string) error     { return nil }
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
func (f *fakeRepo) UpsertFromSAML(_ context.Context, _, _, _, _ string, _ []string, _ domain.MergeStrategy) (domain.User, bool, error) {
	return f.user, f.created, f.err
}

// fakeIssuer captures the arguments passed to IssueIDTokenWithAMR.
type fakeIssuer struct {
	token   string
	lastAMR []string
	err     error
}

func (f *fakeIssuer) IssueIDTokenWithAMR(u *domain.User, amr []string) (string, int, error) {
	f.lastAMR = amr
	return f.token, 3600, f.err
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
