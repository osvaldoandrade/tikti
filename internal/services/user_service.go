package services

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// UserService exposes all account-management operations used by the controllers.
type UserService interface {
	SignUp(ctx context.Context, req domain.SignUpReq) (*domain.SignUpResp, error)
	SignIn(ctx context.Context, req domain.SignInReq) (*domain.SignInResp, error)
	Lookup(ctx context.Context, req domain.LookupReq) (*domain.LookupResp, error)
	TokenExchange(ctx context.Context, req domain.TokenExchangeReq) (*domain.TokenExchangeResp, error)
	JWKS(ctx context.Context) (map[string]any, error)
	ValidateAccessToken(ctx context.Context, tokenString string, issuer string, audience string) (jwt.MapClaims, error)
	SetStatus(ctx context.Context, email string, status string) (*domain.StatusResp, error)
	RevokeTokens(ctx context.Context, email string, tenantID string, scope string) (*domain.RevokeResp, error)
	UpdateUser(ctx context.Context, req domain.UpdateReq) (*domain.UpdateResp, error)
	DeleteUser(ctx context.Context, req domain.DeleteReq) error
	SendOob(ctx context.Context, req domain.SendOobReq) (*domain.SendOobResp, error)
	ResetPassword(ctx context.Context, req domain.ResetPwdReq) error
	GetAllUsers(ctx context.Context) ([]*domain.User, error)
}

// userService is the concrete UserService backed by the repository and JWT utilities.
type userService struct {
	repo            repository.UserRepository
	membershipRepo  repository.MembershipRepository
	jwtSecret       string
	issuerBaseURL   string
	defaultAudience string
	jwksPrivateKey  string
	jwksKeyID       string
	roleSvc         RoleService
	clientSvc       ClientService
	rsaOnce         sync.Once
	rsaKey          interface{}
	rsaErr          error
}

// NewUserService builds a service instance that signs JWTs with the provided secret.
func NewUserService(r repository.UserRepository, membershipRepo repository.MembershipRepository, roleSvc RoleService, clientSvc ClientService, jwtSecret string, issuerBaseURL string, defaultAudience string, jwksPrivateKey string, jwksKeyID string) UserService {
	return &userService{
		repo:            r,
		membershipRepo:  membershipRepo,
		roleSvc:         roleSvc,
		clientSvc:       clientSvc,
		jwtSecret:       jwtSecret,
		issuerBaseURL:   issuerBaseURL,
		defaultAudience: defaultAudience,
		jwksPrivateKey:  jwksPrivateKey,
		jwksKeyID:       jwksKeyID,
	}
}

// SignUp validates uniqueness, hashes the password and persists a new user.
func (s *userService) SignUp(ctx context.Context, req domain.SignUpReq) (*domain.SignUpResp, error) {
	existing, _ := s.repo.FindByEmail(ctx, req.Email)
	if existing != nil {
		return nil, domain.ErrEmailExists
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	role := domain.RoleCompanyEmployee
	if req.Role != "" {
		role = domain.UserRole(req.Role)
	}
	u := &domain.User{
		Id:        uuid.NewString(),
		Email:     req.Email,
		Password:  string(hash),
		Role:      role,
		Status:    domain.UserStatusActive,
		CreatedAt: time.Now(),
	}
	if er := s.repo.CreateUser(ctx, u); er != nil {
		return nil, er
	}
	if s.membershipRepo != nil {
		_ = s.membershipRepo.Create(ctx, &domain.Membership{
			Id:        uuid.NewString(),
			TenantId:  "default",
			UserId:    u.Id,
			Roles:     []string{string(role)},
			CreatedAt: time.Now(),
		})
	}
	return &domain.SignUpResp{
		LocalId:   u.Id,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
	}, nil
}

// SignIn verifies credentials and returns a signed JWT alongside metadata.
func (s *userService) SignIn(ctx context.Context, req domain.SignInReq) (*domain.SignInResp, error) {
	u, err := s.repo.FindByEmail(ctx, req.Email)
	if err != nil || u == nil {
		return nil, domain.ErrInvalidCreds
	}
	if u.Status == domain.UserStatusSuspended {
		return nil, domain.ErrInvalidCreds
	}
	if e := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(req.Password)); e != nil {
		return nil, domain.ErrInvalidCreds
	}
	claims := jwt.MapClaims{
		"userId": u.Id,
		"email":  u.Email,
		"role":   u.Role,
		"iss":    s.issuerBaseURL,
		"aud":    s.defaultAudience,
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, e2 := tok.SignedString([]byte(s.jwtSecret))
	if e2 != nil {
		return nil, e2
	}
	return &domain.SignInResp{
		IdToken:   signed,
		Email:     u.Email,
		LocalId:   u.Id,
		ExpiresIn: 3600,
	}, nil
}

// Lookup converts an idToken into a LookupResp by pulling the stored user.
func (s *userService) Lookup(ctx context.Context, req domain.LookupReq) (*domain.LookupResp, error) {
	claims, e := utils.ParseToken(req.IdToken, s.jwtSecret)
	if e != nil {
		return nil, domain.ErrInvalidToken
	}
	email, _ := claims["email"].(string)
	u, _ := s.repo.FindByEmail(ctx, email)
	if u == nil {
		return nil, domain.ErrNotFound
	}
	return &domain.LookupResp{
		Users: []domain.UserInfo{{
			LocalId: u.Id,
			Email:   u.Email,
			Role:    string(u.Role),
			Status:  string(u.Status),
			Tenant:  s.resolveTenantID(ctx, u),
		}},
	}, nil
}

// TokenExchange exchanges an idToken for a scoped RS256 access token.
func (s *userService) TokenExchange(ctx context.Context, req domain.TokenExchangeReq) (*domain.TokenExchangeResp, error) {
	if strings.TrimSpace(req.IdToken) == "" {
		return nil, domain.ErrInvalidToken
	}
	if strings.TrimSpace(req.Audience) == "" {
		return nil, domain.ErrInvalidAudience
	}

	claims, err := utils.ParseToken(req.IdToken, s.jwtSecret)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	email, _ := claims["email"].(string)
	if email == "" {
		return nil, domain.ErrInvalidToken
	}
	u, _ := s.repo.FindByEmail(ctx, email)
	if u == nil {
		return nil, domain.ErrNotFound
	}
	if u.Status == domain.UserStatusSuspended {
		return nil, domain.ErrInvalidCreds
	}

	tenantID := strings.TrimSpace(req.TenantID)
	memberTenants := s.listTenantIDs(ctx, u.Id)
	if tenantID == "" {
		if len(memberTenants) > 0 {
			tenantID = memberTenants[0]
		} else {
			tenantID = derefString(u.CompanyId)
		}
	}
	if tenantID == "" {
		return nil, domain.ErrInvalidTenant
	}
	if len(memberTenants) > 0 && !containsString(memberTenants, tenantID) {
		return nil, domain.ErrInvalidTenant
	}
	if len(memberTenants) == 0 && u.CompanyId != nil && *u.CompanyId != tenantID {
		return nil, domain.ErrInvalidTenant
	}

	scopes := normalizeList(req.Scopes)
	if s.clientSvc != nil {
		client, err := s.clientSvc.GetClient(ctx, tenantID, req.Audience)
		if err != nil {
			return nil, err
		}
		if client == nil {
			return nil, domain.ErrInvalidAudience
		}
		if client.Status != "ACTIVE" {
			return nil, domain.ErrInvalidAudience
		}
		if len(scopes) == 0 {
			scopes = append(scopes, client.DefaultScopes...)
		}
		if !subset(scopes, client.DefaultScopes) && len(client.DefaultScopes) > 0 {
			return nil, domain.ErrUnauthorizedScope
		}
	}
	if len(scopes) > 0 && !s.scopesAllowed(ctx, tenantID, u, scopes) {
		return nil, domain.ErrUnauthorizedScope
	}

	eventTypes := normalizeList(req.EventTypes)
	if req.Audience == "codeq-worker" && len(eventTypes) == 0 {
		return nil, domain.ErrInvalidArgument
	}

	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 3600
	}
	if ttl > 86400 {
		ttl = 86400
	}

	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		subject = u.Id
	}

	key, err := s.getRSAPrivateKey()
	if err != nil {
		return nil, err
	}

	scopeString := strings.Join(scopes, " ")
	claimsOut := jwt.MapClaims{
		"iss": s.issuerBaseURL,
		"aud": req.Audience,
		"sub": subject,
		"tid": tenantID,
		"ver": u.TokenVersion,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Duration(ttl) * time.Second).Unix(),
		"jti": uuid.NewString(),
	}
	if scopeString != "" {
		claimsOut["scope"] = scopeString
	}
	if len(eventTypes) > 0 {
		claimsOut["eventTypes"] = eventTypes
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claimsOut)
	if s.jwksKeyID != "" {
		token.Header["kid"] = s.jwksKeyID
	}
	signed, err := token.SignedString(key)
	if err != nil {
		return nil, err
	}
	return &domain.TokenExchangeResp{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   ttl,
	}, nil
}

// ValidateAccessToken validates an RS256 access token and enforces token version.
func (s *userService) ValidateAccessToken(ctx context.Context, tokenString string, issuer string, audience string) (jwt.MapClaims, error) {
	key, err := s.getRSAPrivateKey()
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid rsa key")
	}
	claims, err := utils.ValidateRS256(tokenString, &priv.PublicKey, issuer, audience)
	if err != nil {
		return nil, err
	}
	ver, _ := claims["ver"].(float64)
	sub, _ := claims["sub"].(string)
	if sub == "" {
		if email, _ := claims["email"].(string); email != "" {
			sub = email
		}
	}
	if sub == "" {
		return nil, domain.ErrInvalidToken
	}
	u, _ := s.repo.FindByEmail(ctx, sub)
	if u == nil {
		return nil, domain.ErrNotFound
	}
	if u.TokenVersion != int(ver) {
		return nil, domain.ErrInvalidToken
	}
	return claims, nil
}

// JWKS returns the current JSON Web Key Set for RS256 verification.
func (s *userService) JWKS(ctx context.Context) (map[string]any, error) {
	key, err := s.getRSAPrivateKey()
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid rsa key")
	}
	jwks, err := utils.BuildJWKS(priv, s.jwksKeyID)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if b, err := jwks.Marshal(); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out, nil
}

func (s *userService) SetStatus(ctx context.Context, email string, status string) (*domain.StatusResp, error) {
	status = strings.TrimSpace(strings.ToUpper(status))
	if email == "" || status == "" {
		return nil, domain.ErrInvalidArgument
	}
	var st domain.UserStatus
	switch status {
	case string(domain.UserStatusActive):
		st = domain.UserStatusActive
	case string(domain.UserStatusInactive):
		st = domain.UserStatusInactive
	case string(domain.UserStatusSuspended):
		st = domain.UserStatusSuspended
	default:
		return nil, domain.ErrInvalidArgument
	}
	u, err := s.repo.SetStatus(ctx, email, st)
	if err != nil {
		return nil, err
	}
	return &domain.StatusResp{
		LocalId: u.Id,
		Email:   u.Email,
		Status:  string(u.Status),
	}, nil
}

func (s *userService) RevokeTokens(ctx context.Context, email string, tenantID string, scope string) (*domain.RevokeResp, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, domain.ErrInvalidArgument
	}
	ver, u, err := s.repo.IncrementTokenVersion(ctx, email)
	if err != nil {
		return nil, err
	}
	_ = tenantID
	_ = scope
	return &domain.RevokeResp{
		LocalId:      u.Id,
		Email:        u.Email,
		TokenVersion: ver,
		RevokedAt:    time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (s *userService) getRSAPrivateKey() (interface{}, error) {
	s.rsaOnce.Do(func() {
		key, err := utils.ParseRSAPrivateKey(s.jwksPrivateKey)
		if err != nil {
			s.rsaErr = err
			return
		}
		s.rsaKey = key
	})
	if s.rsaErr != nil {
		return nil, s.rsaErr
	}
	if s.rsaKey == nil {
		return nil, errors.New("rsa private key missing")
	}
	return s.rsaKey, nil
}

func (s *userService) scopesAllowed(ctx context.Context, tenantID string, u *domain.User, scopes []string) bool {
	if u == nil {
		return false
	}
	if u.Role == domain.RoleAdmin || u.Role == domain.RoleCompanyAdmin {
		return true
	}
	roles := []string{string(u.Role)}
	if s.membershipRepo != nil {
		if m, _ := s.membershipRepo.Get(ctx, tenantID, u.Id); m != nil {
			roles = append(roles, m.Roles...)
		}
	}
	allowed := map[string]struct{}{}
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		switch r {
		case string(domain.RoleCompanyEmployee):
			for _, p := range []string{"codeq:claim", "codeq:heartbeat", "codeq:abandon", "codeq:nack", "codeq:result", "codeq:subscribe"} {
				allowed[p] = struct{}{}
			}
		default:
		}
		if s.roleSvc != nil {
			if perms, err := s.roleSvc.ResolvePermissions(ctx, tenantID, []string{r}); err == nil {
				for _, p := range perms {
					allowed[p] = struct{}{}
				}
			}
		}
	}
	for _, sc := range scopes {
		if _, ok := allowed[sc]; !ok {
			return false
		}
	}
	return true
}

func normalizeList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func (s *userService) listTenantIDs(ctx context.Context, userID string) []string {
	if s.membershipRepo == nil || userID == "" {
		return nil
	}
	ids, err := s.membershipRepo.ListTenantIDsByUser(ctx, userID)
	if err != nil {
		return nil
	}
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids)
	return ids
}

func (s *userService) resolveTenantID(ctx context.Context, u *domain.User) string {
	if u == nil {
		return ""
	}
	ids := s.listTenantIDs(ctx, u.Id)
	if len(ids) > 0 {
		return ids[0]
	}
	return derefString(u.CompanyId)
}

func containsString(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func subset(items []string, allowed []string) bool {
	if len(items) == 0 {
		return true
	}
	allowedSet := map[string]struct{}{}
	for _, a := range allowed {
		if a == "" {
			continue
		}
		allowedSet[a] = struct{}{}
	}
	for _, item := range items {
		if item == "" {
			continue
		}
		if _, ok := allowedSet[item]; !ok {
			return false
		}
	}
	return true
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// UpdateUser allows authenticated users to change email and/or password.
func (s *userService) UpdateUser(ctx context.Context, req domain.UpdateReq) (*domain.UpdateResp, error) {
	claims, er := utils.ParseToken(req.IdToken, s.jwtSecret)
	if er != nil {
		return nil, er
	}
	email, _ := claims["email"].(string)
	u, findErr := s.repo.FindByEmail(ctx, email)
	if findErr != nil || u == nil {
		return nil, domain.ErrNotFound
	}
	if req.Email != "" {
		u.Email = req.Email
	}
	if req.Password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		u.Password = string(hash)
	}
	if e2 := s.repo.UpdateUser(ctx, u); e2 != nil {
		return nil, e2
	}
	return &domain.UpdateResp{
		LocalId: u.Id,
		Email:   u.Email,
	}, nil
}

// DeleteUser removes the authenticated user identified by the idToken.
func (s *userService) DeleteUser(ctx context.Context, req domain.DeleteReq) error {
	claims, er := utils.ParseToken(req.IdToken, s.jwtSecret)
	if er != nil {
		return er
	}
	email, _ := claims["email"].(string)
	return s.repo.DeleteByEmail(ctx, email)
}

// SendOob generates a one-time code and stores payload metadata for subsequent resets.
func (s *userService) SendOob(ctx context.Context, req domain.SendOobReq) (*domain.SendOobResp, error) {
	u, e := s.repo.FindByEmail(ctx, req.Email)
	if e != nil || u == nil {
		return nil, domain.ErrNotFound
	}
	code := uuid.NewString()
	if err := s.repo.SaveOobCode(ctx, code, req.Email, req.RequestType); err != nil {
		return nil, err
	}
	return &domain.SendOobResp{
		Kind:    "identitytoolkit#GetOobConfirmationCodeResponse",
		Email:   req.Email,
		OobCode: code,
	}, nil
}

// ResetPassword exchanges an OOB code for the stored email and updates the password hash.
func (s *userService) ResetPassword(ctx context.Context, req domain.ResetPwdReq) error {
	email, e := s.repo.GetEmailByOobCode(ctx, req.OobCode)
	if e != nil {
		return domain.ErrInvalidOob
	}
	u, e2 := s.repo.FindByEmail(ctx, email)
	if e2 != nil || u == nil {
		return domain.ErrNotFound
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	u.Password = string(hash)
	if e3 := s.repo.UpdateUser(ctx, u); e3 != nil {
		return e3
	}
	return s.repo.DeleteOobCode(ctx, req.OobCode)
}

// GetAllUsers retrieves every stored user without filtering, mainly for administrative use.
func (s *userService) GetAllUsers(ctx context.Context) ([]*domain.User, error) {
	return s.repo.GetAllUsers(ctx)
}
