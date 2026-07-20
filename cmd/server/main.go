package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/config"
	"github.com/ShifdLabs/shifd-identity-service/db"
	"github.com/ShifdLabs/shifd-identity-service/handler"
	"github.com/ShifdLabs/shifd-identity-service/pkg/jwtutil"
	"github.com/ShifdLabs/shifd-identity-service/repository"
	"github.com/ShifdLabs/shifd-identity-service/router"
	"github.com/ShifdLabs/shifd-identity-service/service"
)

// shutdownTimeout bounds how long in-flight requests get to drain on shutdown.
const shutdownTimeout = 10 * time.Second

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
		cfg,
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
	srv := &http.Server{Addr: addr, Handler: engine}

	// Run the server in a goroutine so main can wait for a shutdown signal.
	go func() {
		log.Printf("main: starting server on %s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("main: server failed: %v", err)
		}
	}()

	// Block until SIGINT/SIGTERM, then drain in-flight requests gracefully.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	stop()

	log.Println("main: shutdown signal received, draining connections...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("main: graceful shutdown failed: %v", err)
	}
	log.Println("main: server stopped")
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
