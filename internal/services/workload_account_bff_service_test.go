package services

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type workloadAccountVerifier struct {
	subject domain.WorkloadSubject
	err     error
}

func (f workloadAccountVerifier) VerifyProjectedToken(context.Context, string) (domain.WorkloadSubject, error) {
	return f.subject, f.err
}

type workloadAccountUsers struct {
	user        *domain.User
	created     *domain.User
	deleted     string
	createError error
}

func (f *workloadAccountUsers) FindByEmail(context.Context, string) (*domain.User, error) {
	return f.user, nil
}
func (f *workloadAccountUsers) CreateUser(_ context.Context, user *domain.User) error {
	if f.createError != nil {
		return f.createError
	}
	copy := *user
	f.created = &copy
	f.user = &copy
	return nil
}
func (f *workloadAccountUsers) DeleteByEmail(_ context.Context, email string) error {
	f.deleted = email
	return nil
}

type workloadAccountMemberships struct {
	membership *domain.Membership
	err        error
}

func (f *workloadAccountMemberships) Get(context.Context, string, string) (*domain.Membership, error) {
	return f.membership, f.err
}

type workloadAccountWriter struct {
	created bool
	err     error
	calls   int
}

func (f *workloadAccountWriter) Ensure(_ context.Context, tenantID, userID string, roles []string) (*domain.Membership, bool, error) {
	f.calls++
	if f.err != nil {
		return nil, false, f.err
	}
	return &domain.Membership{
		Id: "membership-1", TenantId: tenantID, UserId: userID,
		Roles: append([]string(nil), roles...), CreatedAt: time.Now(),
	}, f.created, nil
}

type workloadAccountTokens struct {
	signIn   domain.SignInReq
	exchange domain.TokenExchangeReq
}

func (f *workloadAccountTokens) SignIn(_ context.Context, request domain.SignInReq) (*domain.SignInResp, error) {
	f.signIn = request
	return &domain.SignInResp{IdToken: "identity-token", LocalId: "user-1", Email: request.Email, ExpiresIn: 3600}, nil
}
func (f *workloadAccountTokens) TokenExchange(_ context.Context, request domain.TokenExchangeReq) (*domain.TokenExchangeResp, error) {
	f.exchange = request
	return &domain.TokenExchangeResp{AccessToken: "access-token", TokenType: "Bearer", ExpiresIn: request.TTLSeconds}, nil
}

func testWorkloadAccountClient() config.WorkloadAccountBFFClientConfig {
	return config.WorkloadAccountBFFClientConfig{
		TenantID: "bereia", Namespace: "workload-bereia", ServiceAccount: "bereia-api",
		Audience: "bereia-api", Role: "bereia-user",
		Scopes: []string{"bereia-api:read", "bereia-api:write"}, TTLSeconds: 900,
	}
}

func testWorkloadAccountSubject() domain.WorkloadSubject {
	return domain.WorkloadSubject{
		Subject:   "system:serviceaccount:workload-bereia:bereia-api",
		Namespace: "workload-bereia", ServiceAccount: "bereia-api",
	}
}

func TestWorkloadAccountBFFRegistersAndReplaysExactTenantMembership(t *testing.T) {
	users := &workloadAccountUsers{}
	writer := &workloadAccountWriter{created: true}
	service := NewWorkloadAccountBFFService(
		workloadAccountVerifier{subject: testWorkloadAccountSubject()}, users,
		&workloadAccountMemberships{}, writer, &workloadAccountTokens{},
		[]config.WorkloadAccountBFFClientConfig{testWorkloadAccountClient()},
	)
	request := domain.WorkloadAccountCredentials{Email: " Reader@Example.com ", Password: "correct horse battery staple"}
	result, created, err := service.Register(context.Background(), "projected-token", request)
	if err != nil || !created || result.LocalId == "" || result.Email != "reader@example.com" ||
		result.TenantID != "bereia" || result.Role != "bereia-user" || users.created == nil || writer.calls != 1 {
		t.Fatalf("register result=%#v created=%t user=%#v calls=%d err=%v", result, created, users.created, writer.calls, err)
	}
	if users.created.CompanyId == nil || *users.created.CompanyId != "bereia" ||
		users.created.Role != domain.RoleCompanyEmployee || users.created.AuthSource != domain.AuthSourcePassword ||
		bcrypt.CompareHashAndPassword([]byte(users.created.Password), []byte(request.Password)) != nil {
		t.Fatalf("stored user = %#v", users.created)
	}

	writer.created = false
	replay, replayCreated, err := service.Register(context.Background(), "projected-token", request)
	if err != nil || replayCreated || replay.LocalId != result.LocalId || writer.calls != 2 {
		t.Fatalf("replay=%#v created=%t calls=%d err=%v", replay, replayCreated, writer.calls, err)
	}
}

func TestWorkloadAccountBFFSessionPinsServerSelectedAuthority(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	users := &workloadAccountUsers{user: &domain.User{
		Id: "user-1", Email: "reader@example.com", Password: string(hash), Status: domain.UserStatusActive,
	}}
	memberships := &workloadAccountMemberships{membership: &domain.Membership{
		TenantId: "bereia", UserId: "user-1", Roles: []string{"bereia-user"}, CreatedAt: time.Now(),
	}}
	tokens := &workloadAccountTokens{}
	service := NewWorkloadAccountBFFService(
		workloadAccountVerifier{subject: testWorkloadAccountSubject()}, users, memberships,
		&workloadAccountWriter{}, tokens, []config.WorkloadAccountBFFClientConfig{testWorkloadAccountClient()},
	)
	result, err := service.Session(context.Background(), "projected-token", domain.WorkloadAccountCredentials{
		Email: "reader@example.com", Password: "correct horse battery staple",
	})
	if err != nil || result.AccessToken != "access-token" || result.LocalId != "user-1" || result.ExpiresIn != 900 {
		t.Fatalf("session=%#v err=%v", result, err)
	}
	want := domain.TokenExchangeReq{
		IdToken: "identity-token", Audience: "bereia-api",
		Scopes: []string{"bereia-api:read", "bereia-api:write"}, TenantID: "bereia", TTLSeconds: 900,
	}
	if !reflect.DeepEqual(tokens.exchange, want) {
		t.Fatalf("exchange=%#v want=%#v", tokens.exchange, want)
	}
}

func TestWorkloadAccountBFFFailsClosed(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	validUser := &domain.User{Id: "user-1", Email: "reader@example.com", Password: string(hash), Status: domain.UserStatusActive}
	tests := []struct {
		name       string
		verifier   workloadAccountVerifier
		user       *domain.User
		membership *domain.Membership
		password   string
		want       error
	}{
		{name: "invalid projected token", verifier: workloadAccountVerifier{err: domain.ErrWorkloadTokenInvalid}, password: "correct horse battery staple", want: domain.ErrWorkloadTokenInvalid},
		{name: "foreign workload", verifier: workloadAccountVerifier{subject: domain.WorkloadSubject{Subject: "system:serviceaccount:workload-other:bereia-api", Namespace: "workload-other", ServiceAccount: "bereia-api"}}, password: "correct horse battery staple", want: domain.ErrWorkloadBindingDenied},
		{name: "wrong password", verifier: workloadAccountVerifier{subject: testWorkloadAccountSubject()}, user: validUser, password: "incorrect horse battery staple", want: domain.ErrInvalidCreds},
		{name: "missing membership", verifier: workloadAccountVerifier{subject: testWorkloadAccountSubject()}, user: validUser, password: "correct horse battery staple", want: domain.ErrWorkloadBindingDenied},
		{name: "foreign role", verifier: workloadAccountVerifier{subject: testWorkloadAccountSubject()}, user: validUser, membership: &domain.Membership{TenantId: "bereia", UserId: "user-1", Roles: []string{"other"}}, password: "correct horse battery staple", want: domain.ErrWorkloadBindingDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewWorkloadAccountBFFService(
				test.verifier, &workloadAccountUsers{user: test.user},
				&workloadAccountMemberships{membership: test.membership},
				&workloadAccountWriter{}, &workloadAccountTokens{},
				[]config.WorkloadAccountBFFClientConfig{testWorkloadAccountClient()},
			)
			_, err := service.Session(context.Background(), "projected-token", domain.WorkloadAccountCredentials{
				Email: "reader@example.com", Password: test.password,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("Session() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestWorkloadAccountBFFRollsBackNewUserWhenMembershipFails(t *testing.T) {
	users := &workloadAccountUsers{}
	service := NewWorkloadAccountBFFService(
		workloadAccountVerifier{subject: testWorkloadAccountSubject()}, users,
		&workloadAccountMemberships{}, &workloadAccountWriter{err: errors.New("storage canary")},
		&workloadAccountTokens{}, []config.WorkloadAccountBFFClientConfig{testWorkloadAccountClient()},
	)
	_, _, err := service.Register(context.Background(), "projected-token", domain.WorkloadAccountCredentials{
		Email: "reader@example.com", Password: "correct horse battery staple",
	})
	if err == nil || users.deleted != "reader@example.com" || users.created == nil {
		t.Fatalf("rollback created=%#v deleted=%q err=%v", users.created, users.deleted, err)
	}
}
