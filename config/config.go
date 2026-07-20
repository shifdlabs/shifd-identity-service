package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// EnvFile is the name of the environment file loaded at startup.
// This project uses app.env instead of the conventional .env.
const EnvFile = "app.env"

type Config struct {
	// Application
	AppEnv     string
	AppPort    string
	AppBaseURL string
	// ActivationBaseURL is the frontend origin the platform-admin activation
	// link points at (where the client lands to set their password). Optional;
	// defaults to defaultActivationBaseURL when unset.
	ActivationBaseURL string

	// Database
	DBHost     string
	DBPort     string
	DBName     string
	DBUser     string
	DBPassword string
	DBSSLMode  string

	// Redis
	RedisHost string
	RedisPort string

	// JWT
	JWTPrivateKeyBase64   string
	JWTPublicKeyBase64    string
	JWTKeyID              string
	JWTAccessTokenExpiry  time.Duration
	JWTRefreshTokenExpiry time.Duration
	JWTIssuer             string

	// Email (Resend)
	ResendAPIKey    string
	ResendFromEmail string
	ResendFromName  string

	// Security
	MaxFailedLogins            int
	AccountLockDurationMinutes int
	FailedLoginWindowMinutes   int
	RateLimitAuthPerMin        int
	CORSAllowedOrigins         []string
	TrustedProxies             []string

	// Platform admin
	PlatformAdminEmails []string
}

// defaultFailedLoginWindowMinutes is the rolling window over which consecutive
// failed login attempts are counted toward the account lockout threshold when
// FAILED_LOGIN_WINDOW_MINUTES is not set.
const defaultFailedLoginWindowMinutes = 15

// defaultActivationBaseURL is the approval-frontend origin used to build the
// activation link when ACTIVATION_BASE_URL is not set (local dev default).
const defaultActivationBaseURL = "http://localhost:5174"

// requiredEnvVars are the variables documented in CLAUDE.md's
// "Environment Variables" section. The app refuses to start without them.
var requiredEnvVars = []string{
	"APP_ENV", "APP_PORT", "APP_BASE_URL",
	"DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_SSLMODE",
	"JWT_PRIVATE_KEY_BASE64", "JWT_PUBLIC_KEY_BASE64", "JWT_KEY_ID",
	"JWT_ACCESS_TOKEN_EXPIRY", "JWT_REFRESH_TOKEN_EXPIRY", "JWT_ISSUER",
	"RESEND_API_KEY", "RESEND_FROM_EMAIL", "RESEND_FROM_NAME",
	"MAX_FAILED_LOGINS", "ACCOUNT_LOCK_DURATION_MINUTES", "RATE_LIMIT_AUTH_PER_MIN",
	"CORS_ALLOWED_ORIGINS", "PLATFORM_ADMIN_EMAILS",
}

// Load reads app.env into the process environment and builds the Config.
// It panics if a required variable is missing or malformed so misconfiguration
// is caught at startup rather than surfacing as a runtime error later.
func Load() *Config {
	if err := godotenv.Load(EnvFile); err != nil {
		log.Printf("config: %s not found, falling back to process environment: %v", EnvFile, err)
	}

	if missing := missingEnvVars(); len(missing) > 0 {
		panic(fmt.Sprintf("config: missing required environment variable(s): %s", strings.Join(missing, ", ")))
	}

	return &Config{
		AppEnv:            os.Getenv("APP_ENV"),
		AppPort:           os.Getenv("APP_PORT"),
		AppBaseURL:        os.Getenv("APP_BASE_URL"),
		ActivationBaseURL: getenvWithDefault("ACTIVATION_BASE_URL", defaultActivationBaseURL),

		DBHost:     os.Getenv("DB_HOST"),
		DBPort:     os.Getenv("DB_PORT"),
		DBName:     os.Getenv("DB_NAME"),
		DBUser:     os.Getenv("DB_USER"),
		DBPassword: os.Getenv("DB_PASSWORD"),
		DBSSLMode:  os.Getenv("DB_SSLMODE"),

		RedisHost: os.Getenv("REDIS_HOST"),
		RedisPort: os.Getenv("REDIS_PORT"),

		JWTPrivateKeyBase64:   os.Getenv("JWT_PRIVATE_KEY_BASE64"),
		JWTPublicKeyBase64:    os.Getenv("JWT_PUBLIC_KEY_BASE64"),
		JWTKeyID:              os.Getenv("JWT_KEY_ID"),
		JWTAccessTokenExpiry:  mustParseDuration("JWT_ACCESS_TOKEN_EXPIRY"),
		JWTRefreshTokenExpiry: mustParseDuration("JWT_REFRESH_TOKEN_EXPIRY"),
		JWTIssuer:             os.Getenv("JWT_ISSUER"),

		ResendAPIKey:    os.Getenv("RESEND_API_KEY"),
		ResendFromEmail: os.Getenv("RESEND_FROM_EMAIL"),
		ResendFromName:  os.Getenv("RESEND_FROM_NAME"),

		MaxFailedLogins:            mustParseInt("MAX_FAILED_LOGINS"),
		AccountLockDurationMinutes: mustParseInt("ACCOUNT_LOCK_DURATION_MINUTES"),
		FailedLoginWindowMinutes:   parseIntWithDefault("FAILED_LOGIN_WINDOW_MINUTES", defaultFailedLoginWindowMinutes),
		RateLimitAuthPerMin:        mustParseInt("RATE_LIMIT_AUTH_PER_MIN"),
		CORSAllowedOrigins:         splitAndTrim(os.Getenv("CORS_ALLOWED_ORIGINS")),
		// TRUSTED_PROXIES is optional. When empty, the router trusts no proxy and
		// derives the client IP from the connection's RemoteAddr, so X-Forwarded-For
		// spoofing cannot defeat per-IP rate limiting / account lockout.
		TrustedProxies: splitAndTrim(os.Getenv("TRUSTED_PROXIES")),

		PlatformAdminEmails: splitAndTrim(os.Getenv("PLATFORM_ADMIN_EMAILS")),
	}
}

func missingEnvVars() []string {
	var missing []string
	for _, key := range requiredEnvVars {
		if strings.TrimSpace(os.Getenv(key)) == "" {
			missing = append(missing, key)
		}
	}
	return missing
}

func mustParseInt(key string) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		panic(fmt.Sprintf("config: environment variable %s must be an integer: %v", key, err))
	}
	return value
}

// parseIntWithDefault parses an optional integer env var, returning fallback
// when it is unset/blank and panicking only when it is set to a non-integer.
func parseIntWithDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		panic(fmt.Sprintf("config: environment variable %s must be an integer: %v", key, err))
	}
	return value
}

func mustParseDuration(key string) time.Duration {
	value, err := time.ParseDuration(os.Getenv(key))
	if err != nil {
		panic(fmt.Sprintf("config: environment variable %s must be a valid duration: %v", key, err))
	}
	return value
}

// getenvWithDefault returns the trimmed env var value, or fallback when unset/blank.
func getenvWithDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func splitAndTrim(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
