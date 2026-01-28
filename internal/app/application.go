package app

import (
	"context"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"

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
