package app

import (
	"strings"

	"github.com/osvaldoandrade/tikti/internal/controllers"
	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/internal/storagests"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"

	"github.com/gin-gonic/gin"
)

// SetupMappings registers every public and protected route with their respective controllers.
func SetupMappings(engine *gin.Engine, cfg *config.Config, userService services.UserService, tenantService services.TenantService, membershipService services.MembershipService, roleService services.RoleService, clientService services.ClientService, workloadService services.WorkloadIdentityService, workloadAccountService services.WorkloadAccountBFFService, samlStore saml.Store, samlMetrics *saml.Metrics) {
	v1 := engine.Group("/v1")

	v1.POST("/accounts/signUp", utils.RequiredApiKeyHeader(cfg.ApiKey), controllers.NewSignUpController(userService, cfg).Handle)
	signInCtrl := controllers.NewSignInController(userService, cfg)
	v1.POST("/accounts/signIn", signInCtrl.Handle)
	v1.POST("/accounts/signInWithOobCode", controllers.NewOobSignInController(userService).Handle)
	v1.GET("/auth/forward", controllers.NewForwardAuthController(userService, workloadService, cfg).Handle)
	v1.GET("/.well-known/jwks.json", controllers.NewJWKSController(userService).Handle)
	workloadCtrl := controllers.NewWorkloadIdentityController(workloadService)
	v1.POST("/workloads/token/exchange", workloadCtrl.Exchange)
	if cfg.WorkloadAccountBFF.Enabled && workloadAccountService != nil {
		accountCtrl := controllers.NewWorkloadAccountBFFController(workloadAccountService)
		v1.POST("/workloads/accounts/register", accountCtrl.Register)
		v1.POST("/workloads/accounts/session", accountCtrl.Session)
		// The production identity edge preserves its externally namespaced path
		// when proxying these two exact operations. Keep the aliases POST-only
		// and bound to the same workload-authenticated controllers as the
		// canonical internal endpoints.
		engine.POST("/identity/v1/workloads/accounts/register", accountCtrl.Register)
		engine.POST("/identity/v1/workloads/accounts/session", accountCtrl.Session)
	}
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
	if (cfg.TenantScopedTokenClaimsV1 || cfg.TenantTargetDiscoveryV2) && clientService != nil {
		managedClient := controllers.NewManagedAudienceClientController(clientService, cfg)
		managedAdmin := v1.Group("/admin/tenants/:tenantId/clients", utils.RequiredApiKeyHeader(cfg.ApiKey))
		managedAdmin.PUT("/code-admin-api:ensure", managedClient.Ensure)
		managedAdmin.PUT("/code-admin-api:ensure/", managedClient.Ensure)
	}
	tenantCtrl := controllers.NewTenantController(tenantService, cfg)
	tenantProvisioning := v1.Group("/tenants")
	tenantProvisioning.Use(utils.RequiredApiKeyHeader(cfg.ApiKey))
	tenantProvisioning.PUT("/:tenantId", tenantCtrl.CreateWithID)
	memberCtrl := controllers.NewMembershipController(membershipService, cfg)
	clientCtrl := controllers.NewClientController(clientService, cfg)
	legacyMembershipAdmin := v1.Group("/tenants/:tenantId/users", utils.RequiredApiKeyHeader(cfg.ApiKey))
	legacyMembershipAdmin.GET("", memberCtrl.List)
	legacyMembershipAdmin.POST("", memberCtrl.Create)
	legacyMembershipAdmin.POST("/remove", memberCtrl.Remove)
	tenantOOB := v1.Group("/tenants/:tenantId/oob", utils.RequiredApiKeyHeader(cfg.ApiKey))
	tenantOOB.POST("/send", controllers.RequireTenantOOBOrchestratorAuthority(cfg), controllers.NewOobDispatchController(userService).Handle)
	legacyCodeAdminReads := v1.Group("/", utils.RequiredApiKeyHeader(cfg.ApiKey))
	legacyCodeAdminReads.GET("/tenants", tenantCtrl.List)
	legacyCodeAdminReads.GET("/tenants/id/:id", tenantCtrl.Get)
	legacyCodeAdminReads.GET("/tenants/:tenantId/roles", roleCtrl.List)
	legacyCodeAdminReads.GET("/tenants/:tenantId/clients", clientCtrl.List)
	legacyCodeAdminReads.GET("/tenants/:tenantId/clients/:clientId", clientCtrl.Get)

	protected := v1.Group("/")
	protected.Use(utils.RequiredApiKeyHeader(cfg.ApiKey))
	{
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
		protected.POST("/tenants", tenantCtrl.Create)
		protected.POST("/tenants/:tenantId/roles", roleCtrl.Create)
		protected.POST("/tenants/:tenantId/clients", clientCtrl.Create)
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
		samlAdmin.GET("", controllers.RequireSAMLAdminReadAuthority(cfg), samlAdminController.Get)
		samlAdmin.PUT("", controllers.RequireSAMLAdminWriteAuthority(cfg), samlAdminController.Put)
		samlAdmin.DELETE("", controllers.RequireSAMLAdminWriteAuthority(cfg), samlAdminController.Delete)
	}
}

func setupStorageSTSMappings(engine *gin.Engine, cfg *config.Config, controller *storagests.Controller) {
	if engine == nil || cfg == nil || !cfg.StorageSTS.Enabled || controller == nil {
		return
	}
	engine.POST("/v1/storage/sts", controller.Handle)
	engine.POST("/v1/storage/sts/", controller.RejectAlias)
	// Deny browser preflight before the global browser CORS middleware is
	// installed. The credential response is intentionally non-browser-readable.
	engine.OPTIONS("/v1/storage/sts", controller.RejectAlias)
	engine.OPTIONS("/v1/storage/sts/", controller.RejectAlias)
}

func setupStorageOIDCMappings(engine *gin.Engine, cfg *config.Config, controller *storagests.OIDCController) {
	if engine == nil || cfg == nil || !cfg.StorageSTS.Enabled || controller == nil {
		return
	}
	engine.GET(storagests.MachineOIDCDiscoveryPath, controller.Discovery)
	engine.GET(storagests.MachineOIDCJWKSPath, controller.JWKS)
	// Register aliases and preflight explicitly so Gin cannot redirect these
	// exact machine endpoints or expose browser-readable metadata through CORS.
	for _, path := range []string{
		storagests.MachineOIDCDiscoveryPath,
		storagests.MachineOIDCDiscoveryPath + "/",
		storagests.MachineOIDCJWKSPath,
		storagests.MachineOIDCJWKSPath + "/",
	} {
		if strings.HasSuffix(path, "/") {
			engine.GET(path, controller.Reject)
		}
		engine.OPTIONS(path, controller.Reject)
	}
}

func setupObjectStorageBrowserMappings(engine *gin.Engine, cfg *config.Config, controller *storagests.AdminController) {
	if engine == nil || cfg == nil || !cfg.ObjectStorageBrowser.Enabled || controller == nil {
		return
	}
	base := "/v1/admin/tenants/:tenantId/storage/buckets/:bucketId"
	routes := engine.Group(base, utils.RequiredApiKeyHeader(cfg.ApiKey))
	routes.GET("/objects", controller.List)
	routes.POST("/objects/upload-url", controller.UploadURL)
	routes.POST("/objects/download-url", controller.DownloadURL)
	paths := []string{"/objects", "/objects/upload-url", "/objects/download-url"}
	if cfg.ObjectStorageBrowser.DeleteEnabled {
		routes.POST("/objects:delete", controller.Delete)
		paths = append(paths, "/objects:delete")
	}
	for _, path := range paths {
		routes.OPTIONS(path, controller.Reject)
		routes.GET(path+"/", controller.Reject)
		routes.POST(path+"/", controller.Reject)
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
