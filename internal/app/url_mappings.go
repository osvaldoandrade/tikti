package app

import (
	"github.com/osvaldoandrade/tikti/internal/controllers"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"

	"github.com/gin-gonic/gin"
)

// SetupMappings registers every public and protected route with their respective controllers.
func SetupMappings(engine *gin.Engine, cfg *config.Config, userService services.UserService, tenantService services.TenantService, membershipService services.MembershipService, roleService services.RoleService, clientService services.ClientService) {
	v1 := engine.Group("/v1")

	v1.POST("/accounts/signUp", controllers.NewSignUpController(userService, cfg).Handle)
	signInCtrl := controllers.NewSignInController(userService, cfg)
	v1.POST("/accounts/signIn", signInCtrl.Handle)
	v1.GET("/.well-known/jwks.json", controllers.NewJWKSController(userService).Handle)

	protected := v1.Group("/")
	protected.Use(utils.ApiKey(cfg.ApiKey))
	{
		tenantCtrl := controllers.NewTenantController(tenantService, cfg)
		memberCtrl := controllers.NewMembershipController(membershipService, cfg)
		roleCtrl := controllers.NewRoleController(roleService, cfg)
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

		protected.POST("/tenants", tenantCtrl.Create)
		protected.GET("/tenants/id/:id", tenantCtrl.Get)
		protected.POST("/tenants/:tenantId/users", memberCtrl.Create)
		protected.POST("/tenants/:tenantId/users/remove", memberCtrl.Remove)
		protected.POST("/tenants/:tenantId/roles", roleCtrl.Create)
		protected.GET("/tenants/:tenantId/roles", roleCtrl.List)
		protected.POST("/tenants/:tenantId/clients", clientCtrl.Create)
		protected.GET("/tenants/:tenantId/clients", clientCtrl.List)
		protected.GET("/tenants/:tenantId/clients/:clientId", clientCtrl.Get)
	}
}
