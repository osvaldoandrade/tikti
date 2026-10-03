package services

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
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

type workloadAccountDirectory struct {
	repository.IdentityDirectoryRepository
	roles []string
	put   *domain.AccessAssignment
}

type workloadAccountReplayDirectory struct {
	repository.IdentityDirectoryRepository
	assignment *domain.AccessAssignment
	puts       int
	gets       int
}

func (f *workloadAccountReplayDirectory) PutAccessAssignment(_ context.Context, tenantID string, principalType domain.AccessPrincipalType, principalID string, roles []string, _ string) (*domain.AccessAssignment, bool, error) {
	f.puts++
	if f.assignment != nil && !slices.Equal(f.assignment.Roles, roles) {
		return nil, false, domain.ErrVersionConflict
	}
	return &domain.AccessAssignment{TenantID: tenantID, PrincipalType: principalType, PrincipalID: principalID, Roles: append([]string(nil), roles...)}, f.assignment == nil, nil
}

func (f *workloadAccountReplayDirectory) GetAccessAssignment(context.Context, string, domain.AccessPrincipalType, string) (*domain.AccessAssignment, error) {
	f.gets++
	return f.assignment, nil
}

func (f *workloadAccountDirectory) PutAccessAssignment(_ context.Context, tenantID string, principalType domain.AccessPrincipalType, principalID string, roles []string, _ string) (*domain.AccessAssignment, bool, error) {
	f.put = &domain.AccessAssignment{TenantID: tenantID, PrincipalType: principalType, PrincipalID: principalID, Roles: append([]string(nil), roles...)}
	return f.put, true, nil
}

func (f *workloadAccountDirectory) GetEffectiveTenantRoles(context.Context, string, string) ([]string, []domain.AccessProvenance, error) {
	return append([]string(nil), f.roles...), nil, nil
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
	signIn      domain.SignInReq
	exchange    domain.TokenExchangeReq
	exchangeErr error
}

type workloadAccountDeletion struct {
	tenantID string
	userID   string
	email    string
	err      error
}

func (f *workloadAccountDeletion) Delete(_ context.Context, tenantID, userID, email string) error {
	f.tenantID, f.userID, f.email = tenantID, userID, email
	return f.err
}

func (f *workloadAccountTokens) SignIn(_ context.Context, request domain.SignInReq) (*domain.SignInResp, error) {
	f.signIn = request
	return &domain.SignInResp{IdToken: "identity-token", LocalId: "user-1", Email: request.Email, ExpiresIn: 3600}, nil
}
func (f *workloadAccountTokens) TokenExchange(_ context.Context, request domain.TokenExchangeReq) (*domain.TokenExchangeResp, error) {
	f.exchange = request
	if f.exchangeErr != nil {
		return nil, f.exchangeErr
	}
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
		&workloadAccountDeletion{},
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

func TestWorkloadAccountBFFUsesExactDirectoryAssignmentsWithoutMembershipRoutes(t *testing.T) {
	users := &workloadAccountUsers{}
	directory := &workloadAccountDirectory{roles: []string{"bereia-user"}}
	service := NewWorkloadAccountBFFService(
		workloadAccountVerifier{subject: testWorkloadAccountSubject()}, users,
		nil, nil, &workloadAccountTokens{}, &workloadAccountDeletion{},
		[]config.WorkloadAccountBFFClientConfig{testWorkloadAccountClient()}, directory,
	)
	credentials := domain.WorkloadAccountCredentials{Email: "reader@example.com", Password: "correct horse battery staple"}
	registered, created, err := service.Register(context.Background(), "projected-token", credentials)
	if err != nil || !created || registered == nil || directory.put == nil ||
		directory.put.TenantID != "bereia" || directory.put.PrincipalID != registered.LocalId ||
		!reflect.DeepEqual(directory.put.Roles, []string{"bereia-user"}) {
		t.Fatalf("directory registration=%#v created=%t assignment=%#v err=%v", registered, created, directory.put, err)
	}
	users.user.Id = "user-1"
	session, err := service.Session(context.Background(), "projected-token", credentials)
	if err != nil || session == nil || session.AccessToken != "access-token" {
		t.Fatalf("directory session=%#v err=%v", session, err)
	}
	directory.roles = []string{"other-role"}
	if _, err := service.Session(context.Background(), "projected-token", credentials); !errors.Is(err, domain.ErrWorkloadBindingDenied) {
		t.Fatalf("session with revoked exact role error=%v", err)
	}
}

func TestWorkloadAccountBFFRegistrationReplayPreservesExistingRoles(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	credentials := domain.WorkloadAccountCredentials{Email: "reader@example.com", Password: "correct horse battery staple"}
	for _, test := range []struct {
		name  string
		roles []string
		want  error
	}{
		{name: "base role alongside admin", roles: []string{"bereia-admin", "bereia-user"}},
		{name: "admin without base role", roles: []string{"bereia-admin"}, want: domain.ErrWorkloadAccountConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			originalRoles := append([]string(nil), test.roles...)
			directory := &workloadAccountReplayDirectory{assignment: &domain.AccessAssignment{
				TenantID: "bereia", PrincipalType: domain.AccessPrincipalUser, PrincipalID: "user-1", Roles: test.roles,
			}}
			users := &workloadAccountUsers{user: &domain.User{
				Id: "user-1", Email: credentials.Email, Password: string(hash), Status: domain.UserStatusActive,
			}}
			service := NewWorkloadAccountBFFService(
				workloadAccountVerifier{subject: testWorkloadAccountSubject()}, users,
				nil, nil, &workloadAccountTokens{}, &workloadAccountDeletion{},
				[]config.WorkloadAccountBFFClientConfig{testWorkloadAccountClient()}, directory,
			)
			result, created, registerErr := service.Register(context.Background(), "projected-token", credentials)
			if !errors.Is(registerErr, test.want) || created || directory.puts != 1 || directory.gets != 1 ||
				!slices.Equal(directory.assignment.Roles, originalRoles) || users.deleted != "" {
				t.Fatalf("replay result=%#v created=%t puts=%d gets=%d roles=%v deleted=%q err=%v", result, created, directory.puts, directory.gets, directory.assignment.Roles, users.deleted, registerErr)
			}
			if test.want == nil && (result == nil || result.LocalId != "user-1") {
				t.Fatalf("valid replay result=%#v", result)
			}
		})
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
		&workloadAccountWriter{}, tokens, &workloadAccountDeletion{},
		[]config.WorkloadAccountBFFClientConfig{testWorkloadAccountClient()},
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

func TestWorkloadAccountBFFSessionScopesFollowExactTenantRoles(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	users := &workloadAccountUsers{user: &domain.User{
		Id: "user-1", Email: "reader@example.com", Password: string(hash), Status: domain.UserStatusActive,
	}}
	client := testWorkloadAccountClient()
	client.AdditionalRoles = []config.WorkloadAccountBFFRoleConfig{{
		Role: "bereia-admin", Scopes: []string{"bereia:inventory:read", "bereia:inventory:write"},
	}}
	tests := []struct {
		name  string
		roles []string
		want  []string
		deny  bool
	}{
		{name: "member", roles: []string{"bereia-user"}, want: []string{"bereia-api:read", "bereia-api:write"}},
		{name: "administrator", roles: []string{"bereia-admin"}, want: []string{"bereia:inventory:read", "bereia:inventory:write"}},
		{name: "combined", roles: []string{"bereia-user", "bereia-admin"}, want: []string{"bereia-api:read", "bereia-api:write", "bereia:inventory:read", "bereia:inventory:write"}},
		{name: "unrelated", roles: []string{"other-admin"}, deny: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := &workloadAccountDirectory{roles: test.roles}
			tokens := &workloadAccountTokens{}
			service := NewWorkloadAccountBFFService(
				workloadAccountVerifier{subject: testWorkloadAccountSubject()}, users,
				nil, nil, tokens, &workloadAccountDeletion{},
				[]config.WorkloadAccountBFFClientConfig{client}, directory,
			)
			_, sessionErr := service.Session(context.Background(), "projected-token", domain.WorkloadAccountCredentials{
				Email: "reader@example.com", Password: "correct horse battery staple",
			})
			if test.deny {
				if !errors.Is(sessionErr, domain.ErrWorkloadBindingDenied) || tokens.exchange.Audience != "" {
					t.Fatalf("unauthorized role exchanged a token: error=%v request=%#v", sessionErr, tokens.exchange)
				}
				return
			}
			if sessionErr != nil || !reflect.DeepEqual(tokens.exchange.Scopes, test.want) {
				t.Fatalf("session error=%v scopes=%v want=%v", sessionErr, tokens.exchange.Scopes, test.want)
			}
		})
	}
}

func TestWorkloadAccountBFFAdminScopesRequireTokenExchangeAuthorization(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	client := testWorkloadAccountClient()
	client.AdditionalRoles = []config.WorkloadAccountBFFRoleConfig{{
		Role: "bereia-admin", Scopes: []string{"bereia:inventory:read"},
	}}
	tokens := &workloadAccountTokens{exchangeErr: domain.ErrUnauthorizedScope}
	service := NewWorkloadAccountBFFService(
		workloadAccountVerifier{subject: testWorkloadAccountSubject()},
		&workloadAccountUsers{user: &domain.User{Id: "user-1", Email: "reader@example.com", Password: string(hash), Status: domain.UserStatusActive}},
		nil, nil, tokens, &workloadAccountDeletion{},
		[]config.WorkloadAccountBFFClientConfig{client},
		&workloadAccountDirectory{roles: []string{"bereia-admin"}},
	)
	_, err = service.Session(context.Background(), "projected-token", domain.WorkloadAccountCredentials{
		Email: "reader@example.com", Password: "correct horse battery staple",
	})
	if !errors.Is(err, domain.ErrWorkloadBindingDenied) || !reflect.DeepEqual(tokens.exchange.Scopes, []string{"bereia:inventory:read"}) {
		t.Fatalf("unauthorized admin scope must fail closed: err=%v scopes=%v", err, tokens.exchange.Scopes)
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
				&workloadAccountDeletion{},
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
		&workloadAccountTokens{}, &workloadAccountDeletion{},
		[]config.WorkloadAccountBFFClientConfig{testWorkloadAccountClient()},
	)
	_, _, err := service.Register(context.Background(), "projected-token", domain.WorkloadAccountCredentials{
		Email: "reader@example.com", Password: "correct horse battery staple",
	})
	if err == nil || users.deleted != "reader@example.com" || users.created == nil {
		t.Fatalf("rollback created=%#v deleted=%q err=%v", users.created, users.deleted, err)
	}
}

func TestWorkloadAccountBFFDeletesOnlyAuthenticatedTenantAccount(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	users := &workloadAccountUsers{user: &domain.User{
		Id: "user-1", Email: "reader@example.com", Password: string(hash), Status: domain.UserStatusActive,
		AuthSource: domain.AuthSourcePassword,
	}}
	memberships := &workloadAccountMemberships{membership: &domain.Membership{
		TenantId: "bereia", UserId: "user-1", Roles: []string{"bereia-user"}, CreatedAt: time.Now(),
	}}
	deletion := &workloadAccountDeletion{}
	service := NewWorkloadAccountBFFService(
		workloadAccountVerifier{subject: testWorkloadAccountSubject()}, users, memberships,
		&workloadAccountWriter{}, &workloadAccountTokens{}, deletion,
		[]config.WorkloadAccountBFFClientConfig{testWorkloadAccountClient()},
	)
	err = service.Delete(context.Background(), "projected-token", domain.WorkloadAccountCredentials{
		Email: " Reader@Example.com ", Password: "correct horse battery staple",
	})
	if err != nil || deletion.tenantID != "bereia" || deletion.userID != "user-1" || deletion.email != "reader@example.com" {
		t.Fatalf("deletion=%#v err=%v", deletion, err)
	}
}
