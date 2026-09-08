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
	"github.com/prometheus/client_golang/prometheus"

	"github.com/osvaldoandrade/tikti/internal/providers"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/internal/storagests"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/internal/workloadidentity"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// Application wires runtime configuration, the Gin engine and the user service.
type Application struct {
	Config *config.Config
	Engine *gin.Engine
	Redis  *redis.Client

	UserService           services.UserService
	TenantSvc             services.TenantService
	RoleSvc               services.RoleService
	ClientSvc             services.ClientService
	WorkloadSvc           services.WorkloadIdentityService
	WorkloadAccountSvc    services.WorkloadAccountBFFService
	DirectorySvc          services.IdentityDirectoryService
	AuthenticationLimiter repository.AuthenticationAttemptLimiter
}

// NewApplication assembles dependencies (Redis, repository, services) using the provided config.
func NewApplication(cfg *config.Config) (*Application, error) {
	if err := validateWorkloadIdentityRuntimeConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.TenantScopedTokenClaimsV1 || cfg.TenantTargetDiscoveryV2 {
		if err := scopepolicy.ValidateCompiled(); err != nil {
			return nil, fmt.Errorf("validate tenant scope policy: %w", err)
		}
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
	directoryRepo := repository.NewIdentityDirectoryRepository(redisClient)
	if _, err := directoryRepo.Backfill(context.Background()); err != nil {
		_ = redisClient.Close()
		return nil, fmt.Errorf("backfill identity directory: %w", err)
	}

	tenantService := services.NewTenantService(tenantRepo)
	roleService := services.NewRoleService(roleRepo)
	clientService := services.NewClientService(clientRepo, services.WithManagedAudienceClients(
		cfg.TenantScopedTokenClaimsV1,
		cfg.TenantScopedTokenClaimsV1Tenants,
	), services.WithDynamicManagedAudienceClients(
		cfg.TenantTargetDiscoveryV2,
		tenantRepo,
	))
	exactTenants, tenantsOK := tenantRepo.(repository.ExactTenantRepository)
	exactRoles, rolesOK := roleRepo.(repository.ExactRoleBatchRepository)
	if !tenantsOK || !rolesOK {
		_ = redisClient.Close()
		return nil, fmt.Errorf("identity directory repositories are unavailable")
	}
	directoryService := services.NewIdentityDirectoryService(
		directoryRepo, userRepo, exactTenants, exactRoles, cfg.IdentityGroupsV1,
		services.WithIdentityDirectoryRateLimits(cfg.HTTP.RateLimits),
	)

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
		services.WithTenantTargetDiscoveryV2(
			cfg.TenantTargetDiscoveryV2,
			cfg.TenantTargetDiscoveryV2PrincipalTenants,
			tenantRepo,
		),
		services.WithTenantDiscoveryMetrics(
			services.NewTenantDiscoveryMetrics(prometheus.DefaultRegisterer),
		),
		services.WithIdentityDirectoryAccess(directoryRepo),
		services.WithAuthenticationRateLimits(cfg.HTTP.RateLimits),
		services.WithPasswordAttemptLimiter(directoryRepo),
		services.WithCurrentPlatformAdministrators(cfg.SAML.PlatformAdministrators),
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
	storageSTSController, err := newStorageSTSController(cfg, workloadService)
	if err != nil {
		return nil, err
	}
	storageAdminController, err := newObjectStorageAdminController(cfg, userService)
	if err != nil {
		return nil, err
	}
	var storageOIDCController *storagests.OIDCController
	if cfg.StorageSTS.Enabled {
		storageOIDCController = storagests.NewOIDCController(
			cfg.IssuerBaseURL,
			cfg.StorageSTS.OIDCJWKSURL,
			userService,
		)
	}
	var workloadAccountService services.WorkloadAccountBFFService
	if cfg.WorkloadAccountBFF.Enabled {
		workloadAccountService = services.NewWorkloadAccountBFFService(
			workloadService,
			userRepo,
			membershipRepo,
			nil,
			userService,
			repository.NewWorkloadAccountDeletionRepo(redisClient),
			cfg.WorkloadAccountBFF.Clients,
			directoryRepo,
		)
	}

	engine := newSafeEngine()
	setupStorageOIDCMappings(engine, cfg, storageOIDCController)
	setupStorageSTSMappings(engine, cfg, storageSTSController)
	setupObjectStorageBrowserMappings(engine, cfg, storageAdminController)
	setupIdentityDirectoryMappings(engine, cfg, directoryService, userService)

	_, _ = tenantService.EnsureDefault(context.Background())

	return &Application{
		Config:                cfg,
		Engine:                engine,
		Redis:                 redisClient,
		UserService:           userService,
		TenantSvc:             tenantService,
		RoleSvc:               roleService,
		ClientSvc:             clientService,
		WorkloadSvc:           workloadService,
		WorkloadAccountSvc:    workloadAccountService,
		DirectorySvc:          directoryService,
		AuthenticationLimiter: directoryRepo,
	}, nil
}

type storageProjectedTokenVerifier struct {
	service services.WorkloadIdentityService
}

func (v storageProjectedTokenVerifier) Verify(ctx context.Context, token string) (domain.WorkloadSubject, error) {
	if v.service == nil {
		return domain.WorkloadSubject{}, domain.ErrWorkloadIdentityUnavailable
	}
	return v.service.VerifyProjectedToken(ctx, token)
}

func newStorageSTSController(cfg *config.Config, workloadService services.WorkloadIdentityService) (*storagests.Controller, error) {
	if cfg == nil || !cfg.StorageSTS.Enabled {
		return nil, nil
	}
	if workloadService == nil || cfg.WorkloadIdentity.Audience != "tikti-workload-exchange" ||
		(cfg.WorkloadIdentity.Issuer != "" && cfg.WorkloadIdentity.ClusterRef == "") {
		return nil, fmt.Errorf("storage STS requires exact workload identity verification")
	}
	for _, provider := range cfg.WorkloadIdentity.Providers {
		if strings.TrimSpace(provider.ClusterRef) == "" {
			return nil, fmt.Errorf("storage STS requires a clusterRef for every workload issuer")
		}
	}
	signer, err := storagests.NewSigner(storagests.SigningConfig{
		Issuer: cfg.IssuerBaseURL, ServiceSubject: cfg.StorageSTS.ServiceSubject,
		KeyID: cfg.JwksKeyID, PrivateKeyPEM: cfg.JwksPrivateKey,
		ServiceAssertionTTL: time.Duration(cfg.StorageSTS.ServiceAssertionTTLSeconds) * time.Second,
		CredentialTTL:       time.Duration(cfg.StorageSTS.CredentialTTLSeconds) * time.Second,
		ReadOnlyPolicy:      cfg.StorageSTS.ReadOnlyPolicy, ReadWritePolicy: cfg.StorageSTS.ReadWritePolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize storage STS signer: %w", err)
	}
	timeout := time.Duration(cfg.StorageSTS.DependencyTimeoutSeconds) * time.Second
	authorizer, err := storagests.NewAuthorizerClient(cfg.StorageSTS.AuthorizerURL, &http.Client{Timeout: timeout}, timeout)
	if err != nil {
		return nil, fmt.Errorf("initialize storage authorizer client")
	}
	minio, err := storagests.NewMinIOClient(cfg.StorageSTS.MinIOSTSEndpoint, &http.Client{Timeout: timeout}, timeout)
	if err != nil {
		return nil, fmt.Errorf("initialize MinIO STS client")
	}
	metrics := storagests.NewMetrics(prometheus.DefaultRegisterer)
	broker, err := storagests.NewService(
		storageProjectedTokenVerifier{service: workloadService}, signer, authorizer, minio,
		cfg.StorageSTS.MaximumConcurrent, metrics,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize storage STS broker: %w", err)
	}
	return storagests.NewController(cfg.StorageSTS.SyntheticAccountID, broker, metrics), nil
}

func newObjectStorageAdminController(cfg *config.Config, userService services.UserService) (*storagests.AdminController, error) {
	if cfg == nil || !cfg.ObjectStorageBrowser.Enabled {
		return nil, nil
	}
	if !cfg.StorageSTS.Enabled || userService == nil {
		return nil, fmt.Errorf("object storage browser requires storage STS and access-token validation")
	}
	signer, err := storagests.NewSigner(storagests.SigningConfig{
		Issuer: cfg.IssuerBaseURL, ServiceSubject: cfg.StorageSTS.ServiceSubject,
		KeyID: cfg.JwksKeyID, PrivateKeyPEM: cfg.JwksPrivateKey,
		ServiceAssertionTTL: time.Duration(cfg.StorageSTS.ServiceAssertionTTLSeconds) * time.Second,
		CredentialTTL:       time.Duration(cfg.StorageSTS.CredentialTTLSeconds) * time.Second,
		ReadOnlyPolicy:      cfg.StorageSTS.ReadOnlyPolicy, ReadWritePolicy: cfg.StorageSTS.ReadWritePolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize administrative storage signer: %w", err)
	}
	timeout := time.Duration(cfg.StorageSTS.DependencyTimeoutSeconds) * time.Second
	authorizer, err := storagests.NewAdminAuthorizerClient(
		cfg.ObjectStorageBrowser.AdminAuthorizerURL,
		&http.Client{Timeout: timeout},
		timeout,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize administrative storage authorizer")
	}
	minio, err := storagests.NewMinIOClient(
		cfg.StorageSTS.MinIOSTSEndpoint,
		&http.Client{Timeout: timeout},
		timeout,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize administrative MinIO client")
	}
	deleteCohortTenants := []string(nil)
	if cfg.ObjectStorageBrowser.DeleteEnabled {
		deleteCohortTenants = cfg.ObjectStorageBrowser.DeleteCohortTenants
	}
	broker, err := storagests.NewAdminServiceWithDelete(
		userService, signer, authorizer, minio, minio,
		cfg.IssuerBaseURL, cfg.DefaultAudience, cfg.ObjectStorageBrowser.CohortTenants,
		deleteCohortTenants,
		cfg.StorageSTS.MaximumConcurrent,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize administrative object storage broker: %w", err)
	}
	return storagests.NewAdminControllerWithMetrics(broker, storagests.NewMetrics(prometheus.DefaultRegisterer)), nil
}

func newWorkloadTokenVerifier(cfg config.WorkloadIdentityConfig) (services.WorkloadTokenVerifier, error) {
	type provider struct {
		clusterRef, issuer, jwksURL, bearerTokenFile, authentication string
	}
	providers := make([]provider, 0, len(cfg.Providers)+1)
	if strings.TrimSpace(cfg.Issuer) != "" {
		providers = append(providers, provider{cfg.ClusterRef, cfg.Issuer, cfg.JWKSURL, cfg.JWKSBearerTokenFile, "none"})
	}
	for _, item := range cfg.Providers {
		providers = append(providers, provider{item.ClusterRef, item.Issuer, item.JWKSURL, item.JWKSBearerTokenFile, item.Authentication})
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
		verifier.WithClusterRef(item.clusterRef)
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
