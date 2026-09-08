package services

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	directoryPasswordMinimum             = 12
	directoryPasswordMaximum             = 1024
	temporaryPasswordChangeAttemptLimit  = 5
	temporaryPasswordChangeAttemptWindow = time.Minute
	// Generated from a public fixed dummy value at bcrypt.DefaultCost. It is
	// used only to equalize the unknown/ineligible-user path and is not a
	// credential for any account.
	temporaryPasswordDummyHash = "$2a$10$E0ITma.2mszCHfbNPAFTK.XtwO7m/I6pZzFSnlhYM6wbTc612RWze" // #nosec G101 -- fixed non-account timing equalizer documented above.
)

type IdentityDirectoryService interface {
	CreateUser(context.Context, domain.DirectoryUserCreateReq) (*domain.DirectoryUser, error)
	ChangeTemporaryPassword(context.Context, domain.TemporaryPasswordChangeReq) error
	GetUser(context.Context, string) (*domain.DirectoryUser, error)
	FindUserByEmail(context.Context, string) (*domain.DirectoryUser, error)
	ListUsers(context.Context, string, string, int) (*domain.DirectoryUserPage, error)
	ListTenantUsers(context.Context, string, string, string, int) (*domain.DirectoryUserPage, error)
	GetUserAccess(context.Context, string) (*domain.DirectoryUserAccess, error)

	CreateGroup(context.Context, domain.IdentityGroupCreateReq) (*domain.IdentityGroup, error)
	GetGroup(context.Context, string) (*domain.IdentityGroupDetail, error)
	ListGroups(context.Context, string, string, int) (*domain.IdentityGroupPage, error)
	PatchGroup(context.Context, string, domain.IdentityGroupPatchReq, string) (*domain.IdentityGroup, error)
	DeleteGroup(context.Context, string, string) (bool, error)
	PutGroupMember(context.Context, string, string, string) (*domain.IdentityGroup, bool, error)
	DeleteGroupMember(context.Context, string, string, string) (*domain.IdentityGroup, bool, error)

	PutAssignment(context.Context, string, domain.AccessPrincipalType, string, []string, string) (*domain.AccessAssignment, bool, error)
	GetAssignment(context.Context, string, domain.AccessPrincipalType, string) (*domain.AccessAssignment, error)
	DeleteAssignment(context.Context, string, domain.AccessPrincipalType, string, string) (bool, error)
	ListAssignments(context.Context, string, string, int) (*domain.AccessAssignmentPage, error)
	GetEffectiveTenantRoles(context.Context, string, string) ([]string, []domain.AccessProvenance, error)
}

type identityDirectoryService struct {
	directory      repository.IdentityDirectoryRepository
	users          repository.UserRepository
	tenants        repository.ExactTenantRepository
	roles          repository.ExactRoleBatchRepository
	groupsWrite    bool
	verifyPassword func(string, string) bool
	rateLimits     config.AuthenticationRateLimitsConfig
}

type IdentityDirectoryServiceOption func(*identityDirectoryService)

func WithIdentityDirectoryRateLimits(limits config.AuthenticationRateLimitsConfig) IdentityDirectoryServiceOption {
	return func(service *identityDirectoryService) {
		service.rateLimits = effectiveAuthenticationRateLimits(limits)
	}
}

func NewIdentityDirectoryService(directory repository.IdentityDirectoryRepository, users repository.UserRepository, tenants repository.ExactTenantRepository, roles repository.ExactRoleBatchRepository, groupsWrite bool, options ...IdentityDirectoryServiceOption) IdentityDirectoryService {
	service := &identityDirectoryService{
		directory: directory, users: users, tenants: tenants, roles: roles,
		groupsWrite: groupsWrite, verifyPassword: utils.VerifyPassword,
		rateLimits: config.DefaultAuthenticationRateLimits(),
	}
	for _, option := range options {
		if option != nil {
			option(service)
		}
	}
	return service
}

func (s *identityDirectoryService) CreateUser(ctx context.Context, request domain.DirectoryUserCreateReq) (*domain.DirectoryUser, error) {
	if s == nil || s.directory == nil || s.users == nil {
		return nil, domain.ErrDirectoryInvariant
	}
	email := normalizeIdentityEmail(request.Email)
	if email == "" || !validDirectoryPassword(request.TemporaryPassword) {
		return nil, domain.ErrInvalidArgument
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(request.TemporaryPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, domain.ErrInvalidArgument
	}
	user := &domain.User{
		Id: uuid.NewString(), Email: email, Password: string(hash), Role: domain.RoleCompanyEmployee,
		Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword,
		PasswordChangeRequired: true, CreatedAt: time.Now().UTC(),
	}
	return s.directory.CreateDirectoryUser(ctx, user)
}

func (s *identityDirectoryService) ChangeTemporaryPassword(ctx context.Context, request domain.TemporaryPasswordChangeReq) error {
	if s == nil || s.directory == nil || s.users == nil {
		return domain.ErrDirectoryInvariant
	}
	email := normalizeIdentityEmail(request.Email)
	if email == "" || !validDirectoryPassword(request.TemporaryPassword) || !validDirectoryPassword(request.NewPassword) || request.TemporaryPassword == request.NewPassword {
		return domain.ErrInvalidArgument
	}
	limit := s.rateLimits.Login
	allowed := true
	var err error
	if clientIP := authenticationClientIP(ctx); clientIP != "" {
		allowed, err = s.directory.AllowAuthenticationAttempt(
			ctx, authenticationBucketTemporaryPasswordIP, clientIP, limit.Requests, time.Duration(limit.WindowSeconds)*time.Second,
		)
	}
	if err == nil && allowed {
		allowed, err = s.directory.AllowAuthenticationAttempt(
			ctx, authenticationBucketTemporaryPasswordEmail, email, limit.Requests, time.Duration(limit.WindowSeconds)*time.Second,
		)
	}
	if err != nil {
		return err
	}
	if !allowed {
		return domain.ErrRateLimited
	}
	user, err := s.users.FindByEmail(ctx, email)
	eligible := err == nil && user != nil && user.Status == domain.UserStatusActive &&
		user.AuthSource == domain.AuthSourcePassword && user.PasswordChangeRequired
	verificationHash := temporaryPasswordDummyHash
	if eligible {
		cost, costErr := bcrypt.Cost([]byte(user.Password))
		if costErr == nil && cost == bcrypt.DefaultCost {
			verificationHash = user.Password
		} else {
			eligible = false
		}
	}
	verifier := s.verifyPassword
	if verifier == nil {
		verifier = utils.VerifyPassword
	}
	passwordMatches := verifier(verificationHash, request.TemporaryPassword)
	if !eligible || !passwordMatches {
		return domain.ErrInvalidCreds
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return domain.ErrInvalidArgument
	}
	return s.directory.ConsumeTemporaryPassword(ctx, user.Id, user.Password, user.TokenVersion, string(hash))
}

func (s *identityDirectoryService) GetUser(ctx context.Context, userID string) (*domain.DirectoryUser, error) {
	if s == nil || s.directory == nil {
		return nil, domain.ErrDirectoryInvariant
	}
	user, err := s.directory.GetDirectoryUser(ctx, userID)
	if err == nil && user == nil {
		err = domain.ErrNotFound
	}
	return user, err
}

func (s *identityDirectoryService) FindUserByEmail(ctx context.Context, email string) (*domain.DirectoryUser, error) {
	if s == nil || s.directory == nil {
		return nil, domain.ErrDirectoryInvariant
	}
	user, err := s.directory.FindDirectoryUserByEmail(ctx, normalizeIdentityEmail(email))
	if err == nil && user == nil {
		err = domain.ErrNotFound
	}
	return user, err
}

func (s *identityDirectoryService) ListUsers(ctx context.Context, search, token string, limit int) (*domain.DirectoryUserPage, error) {
	if s == nil || s.directory == nil {
		return nil, domain.ErrDirectoryInvariant
	}
	return s.directory.ListDirectoryUsers(ctx, search, token, limit)
}

func (s *identityDirectoryService) ListTenantUsers(ctx context.Context, tenantID, search, token string, limit int) (*domain.DirectoryUserPage, error) {
	if s == nil || s.directory == nil {
		return nil, domain.ErrDirectoryInvariant
	}
	return s.directory.ListTenantDirectoryUsers(ctx, tenantID, search, token, limit)
}

func (s *identityDirectoryService) GetUserAccess(ctx context.Context, userID string) (*domain.DirectoryUserAccess, error) {
	if s == nil || s.directory == nil {
		return nil, domain.ErrDirectoryInvariant
	}
	return s.directory.GetEffectiveUserAccess(ctx, userID)
}

func (s *identityDirectoryService) CreateGroup(ctx context.Context, request domain.IdentityGroupCreateReq) (*domain.IdentityGroup, error) {
	if err := s.requireGroupMutation(); err != nil {
		return nil, err
	}
	return s.directory.CreateGroup(ctx, request.Name, request.Description)
}
func (s *identityDirectoryService) GetGroup(ctx context.Context, groupID string) (*domain.IdentityGroupDetail, error) {
	if s == nil || s.directory == nil {
		return nil, domain.ErrDirectoryInvariant
	}
	group, err := s.directory.GetGroupDetail(ctx, groupID)
	if err == nil && group == nil {
		err = domain.ErrNotFound
	}
	return group, err
}
func (s *identityDirectoryService) ListGroups(ctx context.Context, search, token string, limit int) (*domain.IdentityGroupPage, error) {
	if s == nil || s.directory == nil {
		return nil, domain.ErrDirectoryInvariant
	}
	return s.directory.ListGroups(ctx, search, token, limit)
}
func (s *identityDirectoryService) PatchGroup(ctx context.Context, groupID string, request domain.IdentityGroupPatchReq, ifMatch string) (*domain.IdentityGroup, error) {
	if err := s.requireGroupMutation(); err != nil {
		return nil, err
	}
	return s.directory.PatchGroup(ctx, groupID, request, ifMatch)
}
func (s *identityDirectoryService) DeleteGroup(ctx context.Context, groupID, ifMatch string) (bool, error) {
	if err := s.requireGroupMutation(); err != nil {
		return false, err
	}
	return s.directory.DeleteGroup(ctx, groupID, ifMatch)
}
func (s *identityDirectoryService) PutGroupMember(ctx context.Context, groupID, userID, ifMatch string) (*domain.IdentityGroup, bool, error) {
	if err := s.requireGroupMutation(); err != nil {
		return nil, false, err
	}
	return s.directory.PutGroupMember(ctx, groupID, userID, ifMatch)
}
func (s *identityDirectoryService) DeleteGroupMember(ctx context.Context, groupID, userID, ifMatch string) (*domain.IdentityGroup, bool, error) {
	if err := s.requireGroupMutation(); err != nil {
		return nil, false, err
	}
	return s.directory.DeleteGroupMember(ctx, groupID, userID, ifMatch)
}

func (s *identityDirectoryService) PutAssignment(ctx context.Context, tenantID string, kind domain.AccessPrincipalType, principalID string, roles []string, ifMatch string) (*domain.AccessAssignment, bool, error) {
	if s == nil || s.directory == nil || s.tenants == nil || s.roles == nil {
		return nil, false, domain.ErrDirectoryInvariant
	}
	if kind == domain.AccessPrincipalGroup && !s.groupsWrite {
		return nil, false, domain.ErrGroupMutationsDisabled
	}
	canonicalRoles := append([]string(nil), roles...)
	for index := range canonicalRoles {
		canonicalRoles[index] = strings.TrimSpace(canonicalRoles[index])
	}
	sort.Strings(canonicalRoles)
	tenant, err := s.tenants.GetExact(ctx, tenantID)
	if err != nil || tenant == nil {
		if err == nil {
			err = domain.ErrNotFound
		}
		return nil, false, err
	}
	if tenant.Status != domain.TenantStatusActive {
		return nil, false, domain.ErrMembershipDependencyInactive
	}
	definitions, err := s.roles.GetManyExact(ctx, tenantID, canonicalRoles)
	if err != nil {
		return nil, false, err
	}
	if len(definitions) != len(canonicalRoles) {
		return nil, false, domain.ErrDirectoryInvariant
	}
	for index, definition := range definitions {
		if definition == nil {
			return nil, false, domain.ErrMembershipDependencyNotFound
		}
		if definition.Name != canonicalRoles[index] || definition.TenantId != tenantID {
			return nil, false, domain.ErrDirectoryInvariant
		}
	}
	return s.directory.PutAccessAssignment(ctx, tenantID, kind, principalID, canonicalRoles, ifMatch)
}

func (s *identityDirectoryService) DeleteAssignment(ctx context.Context, tenantID string, kind domain.AccessPrincipalType, principalID, ifMatch string) (bool, error) {
	if s == nil || s.directory == nil {
		return false, domain.ErrDirectoryInvariant
	}
	if kind == domain.AccessPrincipalGroup && !s.groupsWrite {
		return false, domain.ErrGroupMutationsDisabled
	}
	return s.directory.DeleteAccessAssignment(ctx, tenantID, kind, principalID, ifMatch)
}
func (s *identityDirectoryService) GetAssignment(ctx context.Context, tenantID string, kind domain.AccessPrincipalType, principalID string) (*domain.AccessAssignment, error) {
	if s == nil || s.directory == nil {
		return nil, domain.ErrDirectoryInvariant
	}
	assignment, err := s.directory.GetAccessAssignment(ctx, tenantID, kind, principalID)
	if err == nil && assignment == nil {
		err = domain.ErrNotFound
	}
	return assignment, err
}
func (s *identityDirectoryService) ListAssignments(ctx context.Context, tenantID, token string, limit int) (*domain.AccessAssignmentPage, error) {
	if s == nil || s.directory == nil {
		return nil, domain.ErrDirectoryInvariant
	}
	return s.directory.ListAccessAssignments(ctx, tenantID, token, limit)
}
func (s *identityDirectoryService) GetEffectiveTenantRoles(ctx context.Context, userID, tenantID string) ([]string, []domain.AccessProvenance, error) {
	if s == nil || s.directory == nil {
		return nil, nil, domain.ErrDirectoryInvariant
	}
	return s.directory.GetEffectiveTenantRoles(ctx, userID, tenantID)
}
func (s *identityDirectoryService) requireGroupMutation() error {
	if s == nil || s.directory == nil {
		return domain.ErrDirectoryInvariant
	}
	if !s.groupsWrite {
		return domain.ErrGroupMutationsDisabled
	}
	return nil
}

func normalizeIdentityEmail(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 3 || len(value) > 254 || strings.Count(value, "@") != 1 || strings.HasPrefix(value, "@") || strings.HasSuffix(value, "@") {
		return ""
	}
	for _, char := range []byte(value) {
		if char < '!' || char > '~' {
			return ""
		}
	}
	return value
}
func validDirectoryPassword(value string) bool {
	return len(value) >= directoryPasswordMinimum && len(value) <= directoryPasswordMaximum && strings.TrimSpace(value) != ""
}
