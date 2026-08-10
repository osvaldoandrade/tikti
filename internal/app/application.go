package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/providers"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/internal/workloadidentity"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

// Application wires runtime configuration, the Gin engine and the user service.
type Application struct {
	Config *config.Config
	Engine *gin.Engine
	Redis  *redis.Client

	UserService services.UserService
	TenantSvc   services.TenantService
	MemberSvc   services.MembershipService
	RoleSvc     services.RoleService
	ClientSvc   services.ClientService
	WorkloadSvc services.WorkloadIdentityService
}

// NewApplication assembles dependencies (Redis, repository, services) using the provided config.
func NewApplication(cfg *config.Config) (*Application, error) {
	if err := validateWorkloadIdentityRuntimeConfig(cfg); err != nil {
		return nil, err
	}
	redisClient, err := providers.NewRedisProvider(cfg)
	if err != nil {
		return nil, fmt.Errorf("init redis provider: %w", err)
	}

	userRepo := repository.NewRedisRepo(redisClient)
	tenantRepo := repository.NewTenantRepo(redisClient)
	membershipRepo := repository.NewMembershipRepo(redisClient)
	roleRepo := repository.NewRoleRepo(redisClient)
	clientRepo := repository.NewClientRepo(redisClient)
	workloadRepo := repository.NewWorkloadBindingRepo(redisClient)

	tenantService := services.NewTenantService(tenantRepo)
	membershipService := services.NewMembershipService(userRepo, membershipRepo)
	roleService := services.NewRoleService(roleRepo)
	clientService := services.NewClientService(clientRepo)

	userService := services.NewUserService(
		userRepo,
		membershipRepo,
		roleService,
		clientService,
		cfg.JwtSecret,
		cfg.IssuerBaseURL,
		cfg.DefaultAudience,
		cfg.JwksPrivateKey,
		cfg.JwksKeyID,
		services.WithTenantScopedTokenClaimsV1(
			cfg.TenantScopedTokenClaimsV1,
			cfg.TenantScopedTokenClaimsV1Tenants,
			tenantRepo,
		),
	)
	workloadVerifier, err := newWorkloadTokenVerifier(cfg.WorkloadIdentity)
	if err != nil {
		return nil, err
	}
	workloadService := services.NewWorkloadIdentityService(
		workloadRepo,
		workloadVerifier,
		cfg.IssuerBaseURL,
		cfg.JwksPrivateKey,
		cfg.JwksKeyID,
		time.Duration(cfg.WorkloadIdentity.AccessTokenTTLSeconds)*time.Second,
	)

	engine := gin.Default()

	_, _ = tenantService.EnsureDefault(context.Background())

	return &Application{
		Config:      cfg,
		Engine:      engine,
		Redis:       redisClient,
		UserService: userService,
		TenantSvc:   tenantService,
		MemberSvc:   membershipService,
		RoleSvc:     roleService,
		ClientSvc:   clientService,
		WorkloadSvc: workloadService,
	}, nil
}

func newWorkloadTokenVerifier(cfg config.WorkloadIdentityConfig) (services.WorkloadTokenVerifier, error) {
	type provider struct {
		issuer, jwksURL, bearerTokenFile, authentication string
	}
	providers := make([]provider, 0, len(cfg.Providers)+1)
	if strings.TrimSpace(cfg.Issuer) != "" {
		providers = append(providers, provider{cfg.Issuer, cfg.JWKSURL, cfg.JWKSBearerTokenFile, "none"})
	}
	for _, item := range cfg.Providers {
		providers = append(providers, provider{item.Issuer, item.JWKSURL, item.JWKSBearerTokenFile, item.Authentication})
	}
	if len(providers) == 0 {
		return nil, nil
	}
	trusted := make(map[string]workloadidentity.TokenVerifier, len(providers))
	for _, item := range providers {
		httpClient := &http.Client{Timeout: time.Duration(cfg.HTTPTimeoutSeconds) * time.Second}
		if item.authentication == "gcp" {
			tokenSource, tokenErr := google.DefaultTokenSource(context.Background(), "https://www.googleapis.com/auth/cloud-platform")
			if tokenErr != nil {
				return nil, fmt.Errorf("init GCP workload identity JWKS authentication: %w", tokenErr)
			}
			httpClient = oauth2.NewClient(context.Background(), tokenSource)
			httpClient.Timeout = time.Duration(cfg.HTTPTimeoutSeconds) * time.Second
		} else if tokenFile := strings.TrimSpace(item.bearerTokenFile); tokenFile != "" {
			transport, transportErr := workloadidentity.NewBearerTokenFileTransport(tokenFile, http.DefaultTransport)
			if transportErr != nil {
				return nil, fmt.Errorf("init workload identity JWKS authentication: %w", transportErr)
			}
			httpClient.Transport = transport
		}
		verifier, verifierErr := workloadidentity.NewJWKSVerifier(
			item.issuer, cfg.Audience, item.jwksURL, httpClient,
			time.Duration(cfg.JWKSCacheTTLSeconds)*time.Second,
		)
		if verifierErr != nil {
			return nil, fmt.Errorf("init workload identity verifier for issuer %q: %w", item.issuer, verifierErr)
		}
		trusted[strings.TrimSpace(item.issuer)] = verifier
	}
	if len(trusted) == 1 {
		for _, verifier := range trusted {
			return verifier, nil
		}
	}
	verifier, err := workloadidentity.NewMultiIssuerVerifier(trusted)
	if err != nil {
		return nil, fmt.Errorf("init multi-cluster workload identity verifier: %w", err)
	}
	return verifier, nil
}

func validateWorkloadIdentityRuntimeConfig(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is required")
	}
	if strings.TrimSpace(cfg.WorkloadIdentity.Issuer) == "" && len(cfg.WorkloadIdentity.Providers) == 0 {
		return nil
	}
	if isUnresolvedPlaceholder(cfg.ApiKey) {
		return fmt.Errorf("workload identity binding administration requires an API key")
	}
	if isUnresolvedPlaceholder(cfg.IssuerBaseURL) || isUnresolvedPlaceholder(cfg.JwksKeyID) {
		return fmt.Errorf("workload identity token issuer and signing key id are required")
	}
	key, err := utils.ParseRSAPrivateKey(cfg.JwksPrivateKey)
	if err != nil {
		return fmt.Errorf("workload identity signing key is invalid: %w", err)
	}
	if key.N.BitLen() < 2048 {
		return fmt.Errorf("workload identity signing key must be at least 2048 bits")
	}
	return nil
}

func isUnresolvedPlaceholder(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || (strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}"))
}

// Run starts the HTTP server on the configured port and logs fatal errors.
func (app *Application) Run() {
	addr := fmt.Sprintf(":%d", app.Config.Port)
	log.Printf("Tikti running at %s\n", addr)
	if err := app.Engine.Run(addr); err != nil {
		log.Fatalf("server run error: %v", err)
	}
}
