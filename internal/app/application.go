package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/providers"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

// Application wires runtime configuration, the Gin engine and the user service.
type Application struct {
	Config *config.Config
	Engine *gin.Engine

	UserService services.UserService
	TenantSvc   services.TenantService
	MemberSvc   services.MembershipService
	RoleSvc     services.RoleService
	ClientSvc   services.ClientService
	RedisClient *redis.Client
}

// NewApplication assembles dependencies (Redis, repository, services) using the provided config.
func NewApplication(cfg *config.Config) (*Application, error) {
	redisClient, err := providers.NewRedisProvider(cfg)
	if err != nil {
		return nil, fmt.Errorf("init redis provider: %w", err)
	}

	userRepo := repository.NewRedisRepo(redisClient)
	tenantRepo := repository.NewTenantRepo(redisClient)
	membershipRepo := repository.NewMembershipRepo(redisClient)
	roleRepo := repository.NewRoleRepo(redisClient)
	clientRepo := repository.NewClientRepo(redisClient)

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
		func(ctx context.Context) (string, error) {
			raw, err := redisClient.HGet(ctx, "companies", "c11d3441-52a9-47b0-ba26-48ecc9350b01").Result()
			if err == redis.Nil {
				return "", nil
			}
			if err != nil {
				return "", err
			}
			var company struct {
				AdminUserID string `json:"adminUserId"`
			}
			if err := json.Unmarshal([]byte(raw), &company); err != nil {
				return "", err
			}
			return company.AdminUserID, nil
		},
	)

	engine := gin.Default()

	_, _ = tenantService.EnsureDefault(context.Background())

	return &Application{
		Config:      cfg,
		Engine:      engine,
		UserService: userService,
		TenantSvc:   tenantService,
		MemberSvc:   membershipService,
		RoleSvc:     roleService,
		ClientSvc:   clientService,
		RedisClient: redisClient,
	}, nil
}

// Run starts the HTTP server on the configured port and logs fatal errors.
func (app *Application) Run() {
	addr := fmt.Sprintf(":%d", app.Config.Port)
	log.Printf("Tikti running at %s\n", addr)
	if err := app.Engine.Run(addr); err != nil {
		log.Fatalf("server run error: %v", err)
	}
}
