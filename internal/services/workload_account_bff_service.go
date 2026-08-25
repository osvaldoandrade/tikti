package services

import (
	"context"
	"errors"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type workloadAccountProjectedTokenVerifier interface {
	VerifyProjectedToken(context.Context, string) (domain.WorkloadSubject, error)
}

type workloadAccountUserStore interface {
	FindByEmail(context.Context, string) (*domain.User, error)
	CreateUser(context.Context, *domain.User) error
	DeleteByEmail(context.Context, string) error
}

type workloadAccountMembershipReader interface {
	Get(context.Context, string, string) (*domain.Membership, error)
}

type workloadAccountTokenService interface {
	SignIn(context.Context, domain.SignInReq) (*domain.SignInResp, error)
	TokenExchange(context.Context, domain.TokenExchangeReq) (*domain.TokenExchangeResp, error)
}

// WorkloadAccountBFFService is the secretless, workload-authenticated account
// boundary used by tenant BFFs such as bereia-api.
type WorkloadAccountBFFService interface {
	Register(context.Context, string, domain.WorkloadAccountCredentials) (*domain.WorkloadAccountRegistrationResp, bool, error)
	Session(context.Context, string, domain.WorkloadAccountCredentials) (*domain.WorkloadAccountSessionResp, error)
}

type workloadAccountBFFService struct {
	verifier    workloadAccountProjectedTokenVerifier
	users       workloadAccountUserStore
	memberships workloadAccountMembershipReader
	writer      MembershipV2WriteService
	tokens      workloadAccountTokenService
	clients     map[string]config.WorkloadAccountBFFClientConfig
	now         func() time.Time
}

func NewWorkloadAccountBFFService(
	verifier workloadAccountProjectedTokenVerifier,
	users workloadAccountUserStore,
	memberships workloadAccountMembershipReader,
	writer MembershipV2WriteService,
	tokens workloadAccountTokenService,
	clients []config.WorkloadAccountBFFClientConfig,
) WorkloadAccountBFFService {
	bySubject := make(map[string]config.WorkloadAccountBFFClientConfig, len(clients))
	for _, client := range clients {
		subject := "system:serviceaccount:" + client.Namespace + ":" + client.ServiceAccount
		client.Scopes = append([]string(nil), client.Scopes...)
		bySubject[subject] = client
	}
	return &workloadAccountBFFService{
		verifier: verifier, users: users, memberships: memberships, writer: writer,
		tokens: tokens, clients: bySubject, now: time.Now,
	}
}

func (s *workloadAccountBFFService) Register(
	ctx context.Context,
	projectedToken string,
	credentials domain.WorkloadAccountCredentials,
) (*domain.WorkloadAccountRegistrationResp, bool, error) {
	client, err := s.authorize(ctx, projectedToken)
	if err != nil {
		return nil, false, err
	}
	credentials, err = validWorkloadAccountCredentials(credentials)
	if err != nil {
		return nil, false, err
	}
	user, created, err := s.ensurePasswordUser(ctx, client, credentials)
	if err != nil {
		return nil, false, err
	}
	membership, _, err := s.writer.Ensure(ctx, client.TenantID, user.Id, []string{client.Role})
	if err != nil || !validWorkloadAccountMembership(membership, client, user.Id) {
		if created {
			_ = s.users.DeleteByEmail(ctx, user.Email)
		}
		if errors.Is(err, domain.ErrMembershipConflict) {
			return nil, false, domain.ErrWorkloadAccountConflict
		}
		return nil, false, domain.ErrWorkloadAccountUnavailable
	}
	return &domain.WorkloadAccountRegistrationResp{
		LocalId: user.Id, Email: user.Email, TenantID: client.TenantID,
		Role: client.Role, CreatedAt: user.CreatedAt,
	}, created, nil
}

func (s *workloadAccountBFFService) Session(
	ctx context.Context,
	projectedToken string,
	credentials domain.WorkloadAccountCredentials,
) (*domain.WorkloadAccountSessionResp, error) {
	client, err := s.authorize(ctx, projectedToken)
	if err != nil {
		return nil, err
	}
	credentials, err = validWorkloadAccountCredentials(credentials)
	if err != nil {
		return nil, err
	}
	if s.users == nil || s.memberships == nil || s.tokens == nil {
		return nil, domain.ErrWorkloadAccountUnavailable
	}
	user, err := s.users.FindByEmail(ctx, credentials.Email)
	if err != nil {
		return nil, domain.ErrWorkloadAccountUnavailable
	}
	if user == nil || user.Status != domain.UserStatusActive ||
		!utils.VerifyPassword(user.Password, credentials.Password) {
		return nil, domain.ErrInvalidCreds
	}
	membership, err := s.memberships.Get(ctx, client.TenantID, user.Id)
	if err != nil {
		return nil, domain.ErrWorkloadAccountUnavailable
	}
	if !validWorkloadAccountMembership(membership, client, user.Id) {
		return nil, domain.ErrWorkloadBindingDenied
	}
	identity, err := s.tokens.SignIn(ctx, domain.SignInReq{
		Email: credentials.Email, Password: credentials.Password, ReturnSecureToken: true,
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCreds) {
			return nil, domain.ErrInvalidCreds
		}
		return nil, domain.ErrWorkloadAccountUnavailable
	}
	if identity == nil || identity.IdToken == "" || identity.LocalId != user.Id || identity.Email != user.Email {
		return nil, domain.ErrWorkloadAccountUnavailable
	}
	exchanged, err := s.tokens.TokenExchange(ctx, domain.TokenExchangeReq{
		IdToken: identity.IdToken, Audience: client.Audience, Scopes: append([]string(nil), client.Scopes...),
		TenantID: client.TenantID, TTLSeconds: client.TTLSeconds,
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCreds) || errors.Is(err, domain.ErrInvalidTenant) ||
			errors.Is(err, domain.ErrUnauthorizedScope) {
			return nil, domain.ErrWorkloadBindingDenied
		}
		return nil, domain.ErrWorkloadAccountUnavailable
	}
	if exchanged == nil || !validWorkloadAccountToken(exchanged.AccessToken) || exchanged.TokenType != "Bearer" ||
		exchanged.ExpiresIn < 1 || exchanged.ExpiresIn > client.TTLSeconds {
		return nil, domain.ErrWorkloadAccountUnavailable
	}
	return &domain.WorkloadAccountSessionResp{
		AccessToken: exchanged.AccessToken, TokenType: exchanged.TokenType,
		LocalId: user.Id, Email: user.Email, ExpiresIn: exchanged.ExpiresIn,
	}, nil
}

func (s *workloadAccountBFFService) authorize(
	ctx context.Context,
	projectedToken string,
) (config.WorkloadAccountBFFClientConfig, error) {
	if s == nil || s.verifier == nil || strings.TrimSpace(projectedToken) == "" {
		return config.WorkloadAccountBFFClientConfig{}, domain.ErrWorkloadTokenInvalid
	}
	subject, err := s.verifier.VerifyProjectedToken(ctx, projectedToken)
	if err != nil {
		return config.WorkloadAccountBFFClientConfig{}, err
	}
	client, allowed := s.clients[subject.Subject]
	if !allowed || subject.Namespace != client.Namespace || subject.ServiceAccount != client.ServiceAccount {
		return config.WorkloadAccountBFFClientConfig{}, domain.ErrWorkloadBindingDenied
	}
	return client, nil
}

func (s *workloadAccountBFFService) ensurePasswordUser(
	ctx context.Context,
	client config.WorkloadAccountBFFClientConfig,
	credentials domain.WorkloadAccountCredentials,
) (*domain.User, bool, error) {
	if s.users == nil || s.writer == nil {
		return nil, false, domain.ErrWorkloadAccountUnavailable
	}
	existing, err := s.users.FindByEmail(ctx, credentials.Email)
	if err != nil {
		return nil, false, domain.ErrWorkloadAccountUnavailable
	}
	if existing != nil {
		if existing.Status != domain.UserStatusActive || !utils.VerifyPassword(existing.Password, credentials.Password) {
			return nil, false, domain.ErrWorkloadAccountConflict
		}
		return existing, false, nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(credentials.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, false, domain.ErrWorkloadAccountUnavailable
	}
	now := s.now().UTC()
	user := &domain.User{
		Id: uuid.NewString(), Email: credentials.Email, Password: string(hash),
		Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive,
		CompanyId: &client.TenantID, CreatedAt: now, AuthSource: domain.AuthSourcePassword,
	}
	if err := s.users.CreateUser(ctx, user); err != nil {
		if !errors.Is(err, domain.ErrEmailExists) {
			return nil, false, domain.ErrWorkloadAccountUnavailable
		}
		winner, findErr := s.users.FindByEmail(ctx, credentials.Email)
		if findErr != nil || winner == nil || winner.Status != domain.UserStatusActive ||
			!utils.VerifyPassword(winner.Password, credentials.Password) {
			return nil, false, domain.ErrWorkloadAccountConflict
		}
		return winner, false, nil
	}
	return user, true, nil
}

func validWorkloadAccountCredentials(
	credentials domain.WorkloadAccountCredentials,
) (domain.WorkloadAccountCredentials, error) {
	credentials.Email = strings.ToLower(strings.TrimSpace(credentials.Email))
	address, err := mail.ParseAddress(credentials.Email)
	if err != nil || address.Address != credentials.Email || len(credentials.Email) > 254 ||
		len(credentials.Password) < 12 || len(credentials.Password) > 72 || strings.ContainsRune(credentials.Password, '\x00') {
		return domain.WorkloadAccountCredentials{}, domain.ErrInvalidArgument
	}
	return credentials, nil
}

func validWorkloadAccountMembership(
	membership *domain.Membership,
	client config.WorkloadAccountBFFClientConfig,
	userID string,
) bool {
	return membership != nil && membership.TenantId == client.TenantID && membership.UserId == userID &&
		!membership.CreatedAt.IsZero() && slices.Equal(membership.Roles, []string{client.Role})
}

func validWorkloadAccountToken(value string) bool {
	return value != "" && len(value) <= 16<<10 && !strings.ContainsAny(value, " \r\n\t;,")
}
