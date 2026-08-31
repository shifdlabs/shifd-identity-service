package router

import (
	"crypto/rsa"
	"log"
	"net/http"

	"github.com/ShifdLabs/shifd-identity-service/config"
	"github.com/ShifdLabs/shifd-identity-service/handler"
	"github.com/ShifdLabs/shifd-identity-service/middleware"
	"github.com/ShifdLabs/shifd-identity-service/repository"
	"github.com/gin-gonic/gin"
)

// registerAuthenticatedRateLimitPerMin is the per-IP limit applied to
// POST /api/auth/register when the caller presents a Bearer token that
// verifies (see middleware.RateLimitRegisterPerMinute) — e.g. an org admin
// bulk-importing new users. Anonymous public registration keeps the stricter
// cfg.RateLimitAuthPerMin limit.
const registerAuthenticatedRateLimitPerMin = 60

// tokenEndpointRateLimitPerMin is the per-IP limit for POST /api/auth/refresh
// and /api/auth/logout. Both are public and hit the DB on every call, so they
// need a ceiling — but a generous one, since many legitimate sessions can sit
// behind one NAT'd IP each refreshing every 15 minutes.
const tokenEndpointRateLimitPerMin = 60

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

	// Trust only the explicitly configured proxies so c.ClientIP() cannot be
	// spoofed via X-Forwarded-For/X-Real-IP. An empty list => trust none, and
	// ClientIP() falls back to the connection RemoteAddr.
	if err := engine.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		log.Fatalf("router: failed to set trusted proxies: %v", err)
	}

	engine.Use(middleware.SecurityHeaders(cfg.AppEnv == "production"))
	engine.Use(middleware.BodyLimit(middleware.MaxRequestBodyBytes))
	engine.Use(middleware.CORS(cfg.CORSAllowedOrigins))

	engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "env": cfg.AppEnv})
	})

	// JWKS — standard well-known path, no /api prefix, public, no auth.
	engine.GET("/.well-known/jwks.json", jwksHandler.JWKS)

	authRateLimiter := middleware.RateLimitPerMinute(cfg.RateLimitAuthPerMin)
	// forgot-password / reset-password get their own per-IP limiter (separate
	// budget from login) to curb email bombing and reset-token hammering.
	passwordResetRateLimiter := middleware.RateLimitPerMinute(cfg.RateLimitAuthPerMin)
	// Register gets a separate limiter: callers with a verified Bearer token
	// (e.g. an org admin doing a bulk import) are held to a higher per-minute
	// budget than anonymous public signups.
	registerRateLimiter := middleware.RateLimitRegisterPerMinute(cfg.RateLimitAuthPerMin, registerAuthenticatedRateLimitPerMin, publicKey, cfg.JWTIssuer)
	// refresh/logout share one per-IP budget: public endpoints that cost a DB
	// query per call must not be free to hammer.
	tokenRateLimiter := middleware.RateLimitPerMinute(tokenEndpointRateLimitPerMin)
	// Change-password verifies current_password with bcrypt; without a limiter a
	// stolen (still-valid) access token could brute-force the current password.
	passwordChangeRateLimiter := middleware.RateLimitPerMinute(cfg.RateLimitAuthPerMin)
	requireAuth := middleware.RequireAuth(publicKey, cfg.JWTIssuer)
	requireAdmin := middleware.RequireAdmin(userRepo)

	api := engine.Group("/api")
	{
		auth := api.Group("/auth")
		{
			// Public endpoints. Login and register are rate limited per IP.
			// Logout is public too: the refresh token itself is the credential,
			// validated against the DB by hash in AuthService.Logout — no
			// Authorization header is required.
			auth.POST("/register", registerRateLimiter, authHandler.Register)
			auth.POST("/login", authRateLimiter, authHandler.Login)
			auth.POST("/refresh", tokenRateLimiter, authHandler.Refresh)
			auth.POST("/logout", tokenRateLimiter, authHandler.Logout)
			auth.POST("/forgot-password", passwordResetRateLimiter, authHandler.ForgotPassword)
			auth.POST("/reset-password", passwordResetRateLimiter, authHandler.ResetPassword)
		}

		me := api.Group("/me", requireAuth)
		{
			me.GET("", userHandler.GetMe)
			me.PATCH("", userHandler.UpdateMe)
			me.PATCH("/password", passwordChangeRateLimiter, userHandler.ChangePassword)
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
			admin.POST("/orgs/:org_id/force-logout", adminHandler.ForceLogoutOrg)
			admin.GET("/users", adminHandler.ListUsers)
			admin.GET("/users/:uid", adminHandler.GetUser)
			admin.POST("/users/:uid/force-logout", adminHandler.ForceLogout)
			admin.PATCH("/users/:uid/active", adminHandler.SetUserActive)
			admin.POST("/activation-link", adminHandler.CreateActivationLink)
			admin.GET("/activity", adminHandler.ListActivity)
		}
	}

	return engine
}
