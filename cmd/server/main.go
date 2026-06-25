package main

import (
	"fmt"
	"log"

	"github.com/ShifdLabs/shifd-identity-service/config"
	"github.com/ShifdLabs/shifd-identity-service/db"
	"github.com/ShifdLabs/shifd-identity-service/handler"
	"github.com/ShifdLabs/shifd-identity-service/pkg/jwtutil"
	"github.com/ShifdLabs/shifd-identity-service/repository"
	"github.com/ShifdLabs/shifd-identity-service/router"
	"github.com/ShifdLabs/shifd-identity-service/service"
)

func main() {
	cfg := config.Load()

	gormDB, err := db.Connect(cfg)
	if err != nil {
		log.Fatalf("main: failed to connect to database: %v", err)
	}

	sqlDB, err := gormDB.DB()
	if err != nil {
		log.Fatalf("main: failed to get underlying sql.DB: %v", err)
	}
	defer sqlDB.Close()

	jwtKeys := loadJWTKeys(cfg)
	log.Printf("main: JWT keys loaded successfully (key_id=%s)", jwtKeys.KeyID)

	// Repositories
	userRepo := repository.NewUserRepository(gormDB)
	refreshTokenRepo := repository.NewRefreshTokenRepository(gormDB)
	orgMembershipRepo := repository.NewOrgMembershipRepository(gormDB)
	subscriptionRepo := repository.NewSubscriptionRepository(gormDB)
	organizationRepo := repository.NewOrganizationRepository(gormDB)

	// Services
	emailService := service.NewEmailService(cfg)
	subscriptionService := service.NewSubscriptionService(subscriptionRepo, orgMembershipRepo)
	authService := service.NewAuthService(
		userRepo,
		refreshTokenRepo,
		orgMembershipRepo,
		subscriptionService,
		emailService,
		cfg,
		jwtKeys.Private,
		jwtKeys.Public,
	)
	orgService := service.NewOrgService(
		gormDB,
		organizationRepo,
		orgMembershipRepo,
		subscriptionRepo,
		subscriptionService,
		userRepo,
		emailService,
	)
	adminService := service.NewAdminService(
		organizationRepo,
		orgMembershipRepo,
		userRepo,
		refreshTokenRepo,
		subscriptionService,
		orgService,
	)
	userService := service.NewUserService(
		userRepo,
		orgMembershipRepo,
		organizationRepo,
		subscriptionService,
	)

	// Handlers
	authHandler := handler.NewAuthHandler(authService)
	jwksHandler := handler.NewJWKSHandler(jwtKeys.Public, jwtKeys.KeyID)
	orgHandler := handler.NewOrgHandler(orgService, subscriptionService)
	adminHandler := handler.NewAdminHandler(adminService, subscriptionService)
	userHandler := handler.NewUserHandler(userService)

	engine := router.New(cfg, authHandler, jwksHandler, orgHandler, adminHandler, userHandler, jwtKeys.Public, userRepo)

	addr := fmt.Sprintf(":%s", cfg.AppPort)
	log.Printf("main: starting server on %s", addr)
	if err := engine.Run(addr); err != nil {
		log.Fatalf("main: server failed: %v", err)
	}
}

// loadJWTKeys loads the RSA key pair used to sign and verify JWTs. It panics
// on failure since the server cannot issue or validate tokens without it.
func loadJWTKeys(cfg *config.Config) *jwtutil.Keys {
	privateKey, err := jwtutil.LoadPrivateKey(cfg.JWTPrivateKeyBase64)
	if err != nil {
		panic(fmt.Sprintf("main: failed to load JWT private key: %v", err))
	}

	publicKey, err := jwtutil.LoadPublicKey(cfg.JWTPublicKeyBase64)
	if err != nil {
		panic(fmt.Sprintf("main: failed to load JWT public key: %v", err))
	}

	return &jwtutil.Keys{
		Private: privateKey,
		Public:  publicKey,
		KeyID:   cfg.JWTKeyID,
	}
}
