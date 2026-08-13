package app

import (
	"github.com/osvaldoandrade/tikti/internal/controllers"
	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"

	"github.com/gin-gonic/gin"
)

// SetupMappings registers every public and protected route with their respective controllers.
func SetupMappings(engine *gin.Engine, cfg *config.Config, userService services.UserService, tenantService services.TenantService, membershipService services.MembershipService, roleService services.RoleService, clientService services.ClientService, workloadService services.WorkloadIdentityService, samlStore saml.Store, samlMetrics *saml.Metrics) {
	v1 := engine.Group("/v1")

	v1.POST("/accounts/signUp", controllers.NewSignUpController(userService, cfg).Handle)
	signInCtrl := controllers.NewSignInController(userService, cfg)
	v1.POST("/accounts/signIn", signInCtrl.Handle)
	v1.POST("/accounts/signInWithOobCode", controllers.NewOobSignInController(userService).Handle)
	v1.GET("/auth/forward", controllers.NewForwardAuthController(userService, workloadService, cfg).Handle)
	v1.GET("/.well-known/jwks.json", controllers.NewJWKSController(userService).Handle)
	workloadCtrl := controllers.NewWorkloadIdentityController(workloadService)
	v1.POST("/workloads/token/exchange", workloadCtrl.Exchange)
	workloadAdmin := v1.Group("/workloads")
	workloadAdmin.Use(utils.RequiredApiKeyHeader(cfg.ApiKey))
	{
		workloadAdmin.POST("/bindings", workloadCtrl.UpsertBinding)
		workloadAdmin.POST("/bindings/revoke", workloadCtrl.RevokeBinding)
	}
	roleCtrl := controllers.NewRoleController(roleService, cfg)
	roleAdmin := v1.Group("/admin/tenants/:tenantId/roles", utils.RequiredApiKeyHeader(cfg.ApiKey))
	roleAdmin.GET("", roleCtrl.ListAdmin)
	roleAdmin.GET("/:roleName", roleCtrl.Get)
	roleAdmin.PUT("/:roleName", roleCtrl.Put)
	if cfg.TenantScopedTokenClaimsV1 && clientService != nil {
		managedClient := controllers.NewManagedAudienceClientController(clientService, cfg)
		managedAdmin := v1.Group("/admin/tenants/:tenantId/clients", utils.RequiredApiKeyHeader(cfg.ApiKey))
		managedAdmin.PUT("/code-admin-api:ensure", managedClient.Ensure)
		managedAdmin.PUT("/code-admin-api:ensure/", managedClient.Ensure)
	}
	tenantCtrl := controllers.NewTenantController(tenantService, cfg)
	tenantProvisioning := v1.Group("/tenants")
	tenantProvisioning.Use(utils.RequiredApiKeyHeader(cfg.ApiKey))
	tenantProvisioning.PUT("/:tenantId", tenantCtrl.CreateWithID)

	protected := v1.Group("/")
	protected.Use(utils.ApiKey(cfg.ApiKey))
	{
		memberCtrl := controllers.NewMembershipController(membershipService, cfg)
		clientCtrl := controllers.NewClientController(clientService, cfg)

		protected.POST("/accounts/signInWithPassword", signInCtrl.Handle)
		protected.POST("/accounts/lookup", controllers.NewLookupController(userService, cfg).Handle)
		protected.POST("/accounts/token/exchange", controllers.NewTokenExchangeController(userService).Handle)
		adminUser := controllers.NewUserAdminController(userService, cfg)
		protected.POST("/accounts/status", adminUser.SetStatus)
		protected.POST("/accounts/revoke", adminUser.Revoke)
		protected.POST("/accounts/validate", controllers.NewValidateController(userService, cfg).Handle)
		protected.POST("/accounts/update", controllers.NewUpdateController(userService, cfg).Handle)
		protected.POST("/accounts/delete", controllers.NewDeleteController(userService, cfg).Handle)
		protected.POST("/accounts/sendOobCode", controllers.NewOobSendController(userService, cfg).Handle)
		protected.POST("/accounts/resetPassword", controllers.NewOobResetController(userService, cfg).Handle)
		protected.POST("/tenants/:tenantId/oob/send", controllers.NewOobDispatchController(userService).Handle)

		protected.POST("/tenants", tenantCtrl.Create)
		protected.GET("/tenants", tenantCtrl.List)
		protected.GET("/tenants/id/:id", tenantCtrl.Get)
		protected.GET("/tenants/:tenantId/users", memberCtrl.List)
		protected.POST("/tenants/:tenantId/users", memberCtrl.Create)
		protected.POST("/tenants/:tenantId/users/remove", memberCtrl.Remove)
		protected.POST("/tenants/:tenantId/roles", roleCtrl.Create)
		protected.GET("/tenants/:tenantId/roles", roleCtrl.List)
		protected.POST("/tenants/:tenantId/clients", clientCtrl.Create)
		protected.GET("/tenants/:tenantId/clients", clientCtrl.List)
		protected.GET("/tenants/:tenantId/clients/:clientId", clientCtrl.Get)
	}

	if samlStore != nil {
		samlAdminController := controllers.NewSAMLAdminController(saml.NewAdminService(
			samlStore,
			saml.MetadataHTTPFetcher{},
			cfg.IssuerBaseURL,
			samlMetrics,
		))
		samlAdmin := v1.Group("/admin/tenants/:tenantId/saml/idp")
		samlAdmin.Use(utils.RequiredApiKeyHeader(cfg.ApiKey))
		samlAdmin.GET("", samlAdminController.Get)
		samlAdmin.PUT("", samlAdminController.Put)
		samlAdmin.DELETE("", samlAdminController.Delete)
	}
}

func setupExactMembershipReadMappings(engine *gin.Engine, cfg *config.Config, service services.ExactMembershipReadService) {
	if engine == nil || cfg == nil || !cfg.ExactMembershipReadRoutesV1 || service == nil {
		return
	}
	controller := controllers.NewExactMembershipReadController(service, cfg)
	routes := engine.Group("/v1/admin/tenants/:tenantId/memberships", exactMembershipContractMarker, utils.RequiredApiKeyHeader(cfg.ApiKey))
	routes.GET("", controller.List)
	routes.GET("/:userId", controller.Get)
}

func exactMembershipContractMarker(c *gin.Context) {
	c.Header("X-Tikti-Contract", "exact-memberships-v1")
	c.Next()
}

func setupMembershipV2WriteMappings(engine *gin.Engine, cfg *config.Config, service services.MembershipV2WriteService) {
	if engine == nil || cfg == nil || !cfg.MembershipV2WriteRoutesV1 || service == nil {
		return
	}
	controller := controllers.NewMembershipV2WriteController(service, cfg)
	routes := engine.Group("/v1/admin/tenants/:tenantId/memberships", membershipV2WriteContractMarker, utils.RequiredApiKeyHeader(cfg.ApiKey))
	routes.PUT("/:userId", controller.Put)
	// Register the slash alias so Gin cannot redirect a privileged write.
	routes.PUT("/:userId/", controller.Put)
}

func membershipV2WriteContractMarker(c *gin.Context) {
	c.Header("X-Tikti-Contract", "membership-v2-write-v1")
	c.Next()
}
