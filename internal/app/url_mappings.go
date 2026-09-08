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
func SetupMappings(engine *gin.Engine, cfg *config.Config, userService services.UserService, tenantService services.TenantService, roleService services.RoleService, clientService services.ClientService, workloadService services.WorkloadIdentityService, workloadAccountService services.WorkloadAccountBFFService, samlStore saml.Store, samlMetrics *saml.Metrics) {
	v1 := engine.Group("/v1")
	currentAdminToken := controllers.RequireCurrentAdminToken(userService, cfg)

	signInCtrl := controllers.NewSignInController(userService, cfg)
	v1.POST("/accounts/signIn", signInCtrl.Handle)
	v1.POST("/accounts/signInWithOobCode", controllers.NewOobSignInController(userService, cfg).Handle)
	v1.GET("/auth/forward", controllers.NewForwardAuthController(userService, workloadService, cfg).Handle)
	v1.GET("/.well-known/jwks.json", controllers.NewJWKSController(userService).Handle)
	workloadCtrl := controllers.NewWorkloadIdentityController(workloadService)
	v1.POST("/workloads/token/exchange", workloadCtrl.Exchange)
	if cfg.WorkloadAccountBFF.Enabled && workloadAccountService != nil {
		accountCtrl := controllers.NewWorkloadAccountBFFController(workloadAccountService)
		v1.POST("/workloads/accounts/register", accountCtrl.Register)
		v1.POST("/workloads/accounts/session", accountCtrl.Session)
		v1.POST("/workloads/accounts/delete", accountCtrl.Delete)
		// The production identity edge preserves its externally namespaced path
		// when proxying these two exact operations. Keep the aliases POST-only
		// and bound to the same workload-authenticated controllers as the
		// canonical internal endpoints.
		engine.POST("/identity/v1/workloads/accounts/register", accountCtrl.Register)
		engine.POST("/identity/v1/workloads/accounts/session", accountCtrl.Session)
		engine.POST("/identity/v1/workloads/accounts/delete", accountCtrl.Delete)
	}
	workloadAdmin := v1.Group("/workloads")
	workloadAdmin.Use(utils.RequiredApiKeyHeader(cfg.ApiKey))
	{
		workloadAdmin.POST("/bindings", workloadCtrl.UpsertBinding)
		workloadAdmin.POST("/bindings/revoke", workloadCtrl.RevokeBinding)
	}
	roleCtrl := controllers.NewRoleController(roleService, cfg)
	roleAdmin := v1.Group("/admin/tenants/:tenantId/roles", utils.RequiredApiKeyHeader(cfg.ApiKey), currentAdminToken)
	roleAdmin.GET("", roleCtrl.ListAdmin)
	roleAdmin.GET("/:roleName", roleCtrl.Get)
	roleAdmin.PUT("/:roleName", roleCtrl.Put)
	clientCtrl := controllers.NewClientController(clientService, cfg)
	if clientService != nil {
		clientAdmin := v1.Group("/admin/tenants/:tenantId/clients", utils.RequiredApiKeyHeader(cfg.ApiKey), currentAdminToken)
		clientAdmin.GET("", clientCtrl.List)
		clientAdmin.POST("", clientCtrl.Create)
		clientAdmin.GET("/:clientId", clientCtrl.Get)
	}
	if (cfg.TenantScopedTokenClaimsV1 || cfg.TenantTargetDiscoveryV2) && clientService != nil {
		managedClient := controllers.NewManagedAudienceClientController(clientService, cfg)
		managedAdmin := v1.Group("/admin/tenants/:tenantId/clients", utils.RequiredApiKeyHeader(cfg.ApiKey), currentAdminToken)
		managedAdmin.PUT("/code-admin-api:ensure", managedClient.Ensure)
		managedAdmin.PUT("/code-admin-api:ensure/", managedClient.Ensure)
	}
	tenantCtrl := controllers.NewTenantController(tenantService, cfg)
	identityAdmin := v1.Group("/admin/identity", utils.RequiredApiKeyHeader(cfg.ApiKey), currentAdminToken)
	identityAdmin.GET("/tenant-inventory", tenantCtrl.List)
	identityAdmin.GET("/tenants/:tenantId", tenantCtrl.Get)
	identityAdmin.PUT("/tenants/:tenantId", tenantCtrl.CreateWithID)
	tenantOOB := v1.Group("/tenants/:tenantId/oob", utils.RequiredApiKeyHeader(cfg.ApiKey), currentAdminToken)
	tenantOOB.POST("/send", controllers.RequireTenantOOBOrchestratorAuthority(cfg), controllers.NewOobDispatchController(userService, cfg).Handle)

	protected := v1.Group("/")
	protected.Use(utils.RequiredApiKeyHeader(cfg.ApiKey))
	{
		protected.POST("/accounts/signInWithPassword", signInCtrl.Handle)
		protected.POST("/accounts/lookup", controllers.NewLookupController(userService, cfg).Handle)
		protected.POST("/accounts/token/exchange", controllers.NewTokenExchangeController(userService, cfg).Handle)
		adminUser := controllers.NewUserAdminController(userService, cfg)
		protected.POST("/accounts/status", currentAdminToken, adminUser.SetStatus)
		protected.POST("/accounts/revoke", currentAdminToken, adminUser.Revoke)
		protected.POST("/accounts/validate", currentAdminToken, controllers.NewValidateController(userService, cfg).Handle)
		protected.POST("/internal/access-tokens:validate", controllers.NewCurrentAccessTokenController(userService, cfg).Validate)
		protected.POST("/accounts/update", controllers.NewUpdateController(userService, cfg).Handle)
		protected.POST("/accounts/delete", controllers.NewDeleteController(userService, cfg).Handle)
	}

	if samlStore != nil {
		samlAdminController := controllers.NewSAMLAdminController(saml.NewAdminService(
			samlStore,
			saml.MetadataHTTPFetcher{},
			cfg.IssuerBaseURL,
			samlMetrics,
		))
		samlAdmin := v1.Group("/admin/tenants/:tenantId/saml/idp")
		samlAdmin.Use(utils.RequiredApiKeyHeader(cfg.ApiKey), currentAdminToken)
		samlAdmin.GET("", controllers.RequireSAMLAdminReadAuthority(cfg), samlAdminController.Get)
		samlAdmin.PUT("", controllers.RequireSAMLAdminWriteAuthority(cfg), samlAdminController.Put)
		samlAdmin.DELETE("", controllers.RequireSAMLAdminWriteAuthority(cfg), samlAdminController.Delete)
	}
}

func setupIdentityDirectoryMappings(engine *gin.Engine, cfg *config.Config, service services.IdentityDirectoryService, tokenService services.UserService) {
	if engine == nil || cfg == nil || service == nil {
		return
	}
	controller := controllers.NewIdentityDirectoryController(service, cfg)
	// Temporary-password rotation is credential-authenticated and issues no
	// session. All administrative directory routes additionally require the
	// private service API key and a validated RS256 administrative bearer.
	engine.POST("/v1/accounts/changeTemporaryPassword", identityDirectoryContractMarker, controller.ChangeTemporaryPassword)
	routes := engine.Group(
		"/v1/admin/identity",
		identityDirectoryContractMarker,
		utils.RequiredApiKeyHeader(cfg.ApiKey),
		controllers.RequireCurrentAdminToken(tokenService, cfg),
	)
	routes.GET("/directory/users", controller.ListUsers)
	routes.POST("/directory/users", controller.CreateUser)
	routes.GET("/directory/users/:userId", controller.GetUser)
	routes.GET("/directory/users/:userId/access", controller.GetUserAccess)
	routes.GET("/directory/groups", controller.ListGroups)
	routes.POST("/directory/groups", controller.CreateGroup)
	routes.GET("/directory/groups/:groupId", controller.GetGroup)
	routes.PATCH("/directory/groups/:groupId", controller.PatchGroup)
	routes.DELETE("/directory/groups/:groupId", controller.DeleteGroup)
	routes.PUT("/directory/groups/:groupId/members/:userId", controller.PutGroupMember)
	routes.DELETE("/directory/groups/:groupId/members/:userId", controller.DeleteGroupMember)
	routes.GET("/tenants/:tenantId/access-assignments", controller.ListAssignments)
	routes.GET("/tenants/:tenantId/access-assignments/users/:userId", controller.GetUserAssignment)
	routes.PUT("/tenants/:tenantId/access-assignments/users/:userId", controller.PutUserAssignment)
	routes.DELETE("/tenants/:tenantId/access-assignments/users/:userId", controller.DeleteUserAssignment)
	routes.PUT("/tenants/:tenantId/access-assignments/groups/:groupId", controller.PutGroupAssignment)
	routes.DELETE("/tenants/:tenantId/access-assignments/groups/:groupId", controller.DeleteGroupAssignment)
}

func identityDirectoryContractMarker(c *gin.Context) {
	c.Header("X-Tikti-Contract", "identity-directory-v2")
	c.Next()
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
