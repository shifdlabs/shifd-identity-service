package router

import (
	"crypto/rsa"
	"net/http"

	"github.com/ShifdLabs/shifd-identity-service/config"
	"github.com/ShifdLabs/shifd-identity-service/handler"
	"github.com/ShifdLabs/shifd-identity-service/middleware"
	"github.com/ShifdLabs/shifd-identity-service/repository"
	"github.com/gin-gonic/gin"
)

// New builds the Gin engine with all routes and middleware wired together.
// publicKey is used by the auth middleware to validate Bearer JWTs locally;
// userRepo is used by the admin middleware to re-check is_platform_admin.
func New(
	cfg *config.Config,
	authHandler *handler.AuthHandler,
	jwksHandler *handler.JWKSHandler,
	orgHandler *handler.OrgHandler,
	adminHandler *handler.AdminHandler,
	userHandler *handler.UserHandler,
	publicKey *rsa.PublicKey,
	userRepo *repository.UserRepository,
) *gin.Engine {
	if cfg.AppEnv == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.Default()
	engine.Use(middleware.CORS(cfg.CORSAllowedOrigins))

	engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "env": cfg.AppEnv})
	})

	// JWKS — standard well-known path, no /api prefix, public, no auth.
	engine.GET("/.well-known/jwks.json", jwksHandler.JWKS)

	authRateLimiter := middleware.RateLimitPerMinute(cfg.RateLimitAuthPerMin)
	requireAuth := middleware.RequireAuth(publicKey)
	requireAdmin := middleware.RequireAdmin(userRepo)

	api := engine.Group("/api")
	{
		auth := api.Group("/auth")
		{
			// Public endpoints. Login and register are rate limited per IP.
			// Logout is public too: the refresh token itself is the credential,
			// validated against the DB by hash in AuthService.Logout — no
			// Authorization header is required.
			auth.POST("/register", authRateLimiter, authHandler.Register)
			auth.POST("/login", authRateLimiter, authHandler.Login)
			auth.POST("/refresh", authHandler.Refresh)
			auth.POST("/logout", authHandler.Logout)
			auth.POST("/forgot-password", authHandler.ForgotPassword)
			auth.POST("/reset-password", authHandler.ResetPassword)
		}

		me := api.Group("/me", requireAuth)
		{
			me.GET("", userHandler.GetMe)
			me.PATCH("", userHandler.UpdateMe)
			me.PATCH("/password", userHandler.ChangePassword)
			me.GET("/orgs", userHandler.ListMyOrgs)
		}

		orgs := api.Group("/orgs", requireAuth)
		{
			orgs.POST("", orgHandler.CreateOrg)
			orgs.GET("/:org_id", orgHandler.GetOrg)
			orgs.POST("/:org_id/members", orgHandler.InviteMember)
			orgs.POST("/:org_id/members/accept", orgHandler.AcceptInvite)
			orgs.GET("/:org_id/members", orgHandler.ListMembers)
			orgs.PATCH("/:org_id/members/:user_id", orgHandler.UpdateMember)
			orgs.DELETE("/:org_id/members/:user_id", orgHandler.RemoveMember)
			orgs.GET("/:org_id/subscriptions", orgHandler.ListSubscriptions)
		}

		admin := api.Group("/admin", requireAuth, requireAdmin)
		{
			admin.GET("/orgs", adminHandler.ListOrgs)
			admin.POST("/orgs", adminHandler.CreateOrg)
			admin.GET("/orgs/:org_id", adminHandler.GetOrg)
			admin.POST("/orgs/:org_id/members", adminHandler.AddMember)
			admin.POST("/orgs/:org_id/subscriptions", adminHandler.CreateSubscription)
			admin.PATCH("/orgs/:org_id/subscriptions/:sub_id", adminHandler.UpdateSubscription)
			admin.GET("/users", adminHandler.ListUsers)
			admin.POST("/users/:uid/force-logout", adminHandler.ForceLogout)
		}
	}

	return engine
}
