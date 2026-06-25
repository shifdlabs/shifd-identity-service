package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strings"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/config"
	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/ShifdLabs/shifd-identity-service/pkg/jwtutil"
	"github.com/ShifdLabs/shifd-identity-service/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	bcryptCost              = 12
	minPasswordLength       = 8
	passwordResetTokenBytes = 32
	passwordResetTokenTTL   = time.Hour
)

// Sentinel errors returned by AuthService. Handlers map these to the
// SNAKE_CASE error codes and HTTP statuses defined in CLAUDE.md.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrEmailAlreadyExists = errors.New("email already registered")
	ErrInvalidEmail       = errors.New("invalid email format")
	ErrPasswordTooShort   = errors.New("password must be at least 8 characters")
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenInvalid       = errors.New("token is invalid")
	ErrForbidden          = errors.New("not an active member of this organization")
)

// AccountLockedError indicates the account is locked until LockTimestamp plus
// the configured lock duration elapses.
type AccountLockedError struct {
	LockTimestamp *time.Time
}

func (e *AccountLockedError) Error() string {
	return "account is locked"
}

// LoginResult is returned by AuthService.Login on success.
// Org is nil if the user has no active org membership (or none matching the
// requested org_id).
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	User         *model.User
	Org          *model.OrgMembership
}

// AuthService implements registration, login, token refresh, logout, and
// password reset business logic.
type AuthService struct {
	userRepo            *repository.UserRepository
	refreshTokenRepo    *repository.RefreshTokenRepository
	orgMembershipRepo   *repository.OrgMembershipRepository
	subscriptionService *SubscriptionService
	emailService        *EmailService
	cfg                 *config.Config
	privateKey          *rsa.PrivateKey
	publicKey           *rsa.PublicKey
}

func NewAuthService(
	userRepo *repository.UserRepository,
	refreshTokenRepo *repository.RefreshTokenRepository,
	orgMembershipRepo *repository.OrgMembershipRepository,
	subscriptionService *SubscriptionService,
	emailService *EmailService,
	cfg *config.Config,
	privateKey *rsa.PrivateKey,
	publicKey *rsa.PublicKey,
) *AuthService {
	return &AuthService{
		userRepo:            userRepo,
		refreshTokenRepo:    refreshTokenRepo,
		orgMembershipRepo:   orgMembershipRepo,
		subscriptionService: subscriptionService,
		emailService:        emailService,
		cfg:                 cfg,
		privateKey:          privateKey,
		publicKey:           publicKey,
	}
}

// Register creates a new user account. phone may be empty.
func (s *AuthService) Register(ctx context.Context, email, password, name, phone string) (*model.User, error) {
	normalizedEmail := normalizeEmail(email)

	if _, err := mail.ParseAddress(normalizedEmail); err != nil {
		return nil, ErrInvalidEmail
	}
	if len(password) < minPasswordLength {
		return nil, ErrPasswordTooShort
	}

	if _, err := s.userRepo.FindByEmail(ctx, normalizedEmail); err == nil {
		return nil, ErrEmailAlreadyExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("auth: failed to check existing email: %w", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to hash password: %w", err)
	}

	user := &model.User{
		Email:           normalizedEmail,
		PasswordHash:    string(hashedPassword),
		Name:            name,
		IsPlatformAdmin: s.isPlatformAdminEmail(normalizedEmail),
	}
	if phone != "" {
		user.Phone = &phone
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("auth: failed to create user: %w", err)
	}

	return user, nil
}

// Login authenticates a user and issues a new access/refresh token pair.
// orgID is optional: if nil, the user's first active org membership (if any)
// is used as the token's org context.
func (s *AuthService) Login(ctx context.Context, email, password string, orgID *uuid.UUID, deviceInfo string) (*LoginResult, error) {
	normalizedEmail := normalizeEmail(email)

	user, err := s.userRepo.FindByEmail(ctx, normalizedEmail)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("auth: failed to look up user: %w", err)
	}

	if user.IsLocked {
		if user.LockTimestamp == nil || time.Since(*user.LockTimestamp) < time.Duration(s.cfg.AccountLockDurationMinutes)*time.Minute {
			return nil, &AccountLockedError{LockTimestamp: user.LockTimestamp}
		}

		// Lock duration has elapsed: auto-unlock and let the attempt proceed.
		user.IsLocked = false
		user.LockTimestamp = nil
		if err := s.userRepo.Update(ctx, user); err != nil {
			return nil, fmt.Errorf("auth: failed to auto-unlock account: %w", err)
		}
		if err := s.userRepo.ResetFailedLogins(ctx, normalizedEmail); err != nil {
			return nil, fmt.Errorf("auth: failed to reset failed logins: %w", err)
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, s.handleFailedLogin(ctx, user)
	}

	if err := s.userRepo.ResetFailedLogins(ctx, normalizedEmail); err != nil {
		return nil, fmt.Errorf("auth: failed to reset failed logins: %w", err)
	}

	membership, products, userLimit, err := s.resolveOrgContext(ctx, user.ID, orgID)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.issueAccessToken(user, membership, products, userLimit)
	if err != nil {
		return nil, err
	}

	rawRefreshToken, err := s.issueRefreshToken(ctx, user.ID, membership, deviceInfo)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: rawRefreshToken,
		User:         user,
		Org:          membership,
	}, nil
}

// handleFailedLogin records a failed password attempt and locks the account
// once MaxFailedLogins is reached, returning the error the caller should surface.
func (s *AuthService) handleFailedLogin(ctx context.Context, user *model.User) error {
	if err := s.userRepo.IncrementFailedLogins(ctx, user.Email, ""); err != nil {
		return fmt.Errorf("auth: failed to record failed login: %w", err)
	}

	count, err := s.userRepo.CountRecentFailedLogins(ctx, user.Email, time.Time{})
	if err != nil {
		return fmt.Errorf("auth: failed to count failed logins: %w", err)
	}

	if int(count) < s.cfg.MaxFailedLogins {
		return ErrInvalidCredentials
	}

	now := time.Now().UTC()
	user.IsLocked = true
	user.LockTimestamp = &now
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("auth: failed to lock account: %w", err)
	}

	return &AccountLockedError{LockTimestamp: &now}
}

// resolveOrgContext picks the org membership (and its active product IDs and
// seat limit) to embed in the JWT. If orgID is non-nil the user must be an
// active member of that org or ErrForbidden is returned. If orgID is nil, the
// user's first active membership is used; a user with no active memberships
// gets a nil membership (no org claims) rather than an error.
func (s *AuthService) resolveOrgContext(ctx context.Context, userID uuid.UUID, orgID *uuid.UUID) (*model.OrgMembership, []string, *int, error) {
	if orgID != nil {
		membership, err := s.orgMembershipRepo.FindByUserAndOrg(ctx, userID, *orgID)
		if err != nil || membership.Status != model.OrgMembershipStatusActive {
			return nil, nil, nil, ErrForbidden
		}

		products, userLimit, err := s.loadProductsAndUserLimit(ctx, membership.OrgID)
		if err != nil {
			return nil, nil, nil, err
		}
		return membership, products, userLimit, nil
	}

	memberships, err := s.orgMembershipRepo.FindAllByUserID(ctx, userID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("auth: failed to load org memberships: %w", err)
	}

	for i := range memberships {
		if memberships[i].Status != model.OrgMembershipStatusActive {
			continue
		}
		membership := memberships[i]
		products, userLimit, err := s.loadProductsAndUserLimit(ctx, membership.OrgID)
		if err != nil {
			return nil, nil, nil, err
		}
		return &membership, products, userLimit, nil
	}

	return nil, nil, nil, nil
}

// loadProductsAndUserLimit returns the active product IDs for orgID plus the
// seat limit to embed in the JWT: the smallest UserLimit among orgID's active
// subscriptions, or nil if none of them carry a limit (unlimited).
func (s *AuthService) loadProductsAndUserLimit(ctx context.Context, orgID uuid.UUID) ([]string, *int, error) {
	subs, err := s.subscriptionService.ListActiveByOrg(ctx, orgID)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: failed to load subscriptions: %w", err)
	}

	products := make([]string, 0, len(subs))
	var userLimit *int
	for _, sub := range subs {
		products = append(products, sub.ProductID)
		if sub.UserLimit != nil && (userLimit == nil || *sub.UserLimit < *userLimit) {
			limit := *sub.UserLimit
			userLimit = &limit
		}
	}
	return products, userLimit, nil
}

func (s *AuthService) issueAccessToken(user *model.User, membership *model.OrgMembership, products []string, userLimit *int) (string, error) {
	claims := buildClaims(user, membership, products, userLimit)
	return jwtutil.GenerateAccessToken(s.privateKey, s.cfg.JWTKeyID, s.cfg.JWTIssuer, s.cfg.JWTAccessTokenExpiry, claims)
}

func (s *AuthService) issueRefreshToken(ctx context.Context, userID uuid.UUID, membership *model.OrgMembership, deviceInfo string) (string, error) {
	raw := uuid.NewString()

	refreshToken := &model.RefreshToken{
		UserID:    userID,
		TokenHash: hashToken(raw),
		ExpiresAt: time.Now().UTC().Add(s.cfg.JWTRefreshTokenExpiry),
	}
	if membership != nil {
		orgID := membership.OrgID
		refreshToken.OrgID = &orgID
	}
	if deviceInfo != "" {
		refreshToken.DeviceInfo = &deviceInfo
	}

	if err := s.refreshTokenRepo.Create(ctx, refreshToken); err != nil {
		return "", fmt.Errorf("auth: failed to create refresh token: %w", err)
	}
	return raw, nil
}

// buildClaims assembles the JWT claims map per the CLAUDE.md JWT Claims
// Structure. org_id/org_role/products/user_limit are omitted when membership
// is nil. user_limit is -1 when the org's active subscriptions carry no seat
// limit (unlimited), keeping the claim an integer for downstream parsing.
func buildClaims(user *model.User, membership *model.OrgMembership, products []string, userLimit *int) map[string]interface{} {
	claims := map[string]interface{}{
		"sub":   user.ID.String(),
		"email": user.Email,
		"name":  user.Name,
	}
	if membership != nil {
		claims["org_id"] = membership.OrgID.String()
		claims["org_role"] = membership.Role
		claims["products"] = products
		if userLimit != nil {
			claims["user_limit"] = *userLimit
		} else {
			claims["user_limit"] = -1
		}
	}
	return claims
}

// Refresh validates rawRefreshToken and issues a new access token. The org
// context is re-derived from current DB state (not trusted from the token),
// and the refresh token itself is never rotated.
func (s *AuthService) Refresh(ctx context.Context, rawRefreshToken string) (string, error) {
	tokenHash := hashToken(rawRefreshToken)

	refreshToken, err := s.refreshTokenRepo.FindByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrTokenInvalid
		}
		return "", fmt.Errorf("auth: failed to look up refresh token: %w", err)
	}
	if refreshToken.RevokedAt != nil {
		return "", ErrTokenInvalid
	}
	if time.Now().UTC().After(refreshToken.ExpiresAt) {
		return "", ErrTokenExpired
	}

	user, err := s.userRepo.FindByID(ctx, refreshToken.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrTokenInvalid
		}
		return "", fmt.Errorf("auth: failed to look up user: %w", err)
	}

	// If the org membership bound to this refresh token is no longer active,
	// degrade gracefully to a token with no org claims rather than failing
	// the refresh outright.
	var membership *model.OrgMembership
	var products []string
	var userLimit *int
	if refreshToken.OrgID != nil {
		candidate, mErr := s.orgMembershipRepo.FindByUserAndOrg(ctx, user.ID, *refreshToken.OrgID)
		if mErr == nil && candidate.Status == model.OrgMembershipStatusActive {
			membership = candidate
			products, userLimit, err = s.loadProductsAndUserLimit(ctx, candidate.OrgID)
			if err != nil {
				return "", err
			}
		}
	}

	return s.issueAccessToken(user, membership, products, userLimit)
}

// Logout revokes the refresh token identified by rawRefreshToken. It is
// idempotent: revoking an unknown or already-revoked token is not an error.
func (s *AuthService) Logout(ctx context.Context, rawRefreshToken string) error {
	tokenHash := hashToken(rawRefreshToken)
	if err := s.refreshTokenRepo.RevokeByTokenHash(ctx, tokenHash); err != nil {
		return fmt.Errorf("auth: failed to revoke refresh token: %w", err)
	}
	return nil
}

// ForgotPassword always returns nil so callers cannot use it to enumerate
// registered emails. Genuine failures (not "user not found") are logged
// internally since the caller never sees them.
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	normalizedEmail := normalizeEmail(email)

	user, err := s.userRepo.FindByEmail(ctx, normalizedEmail)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("auth: forgot-password lookup failed for %s: %v", normalizedEmail, err)
		}
		return nil
	}

	rawToken, err := generateSecureToken(passwordResetTokenBytes)
	if err != nil {
		log.Printf("auth: failed to generate reset token for %s: %v", normalizedEmail, err)
		return nil
	}

	resetToken := &model.PasswordResetToken{
		UserID:    user.ID,
		TokenHash: hashToken(rawToken),
		ExpiresAt: time.Now().UTC().Add(passwordResetTokenTTL),
	}
	if err := s.userRepo.CreatePasswordResetToken(ctx, resetToken); err != nil {
		log.Printf("auth: failed to store reset token for %s: %v", normalizedEmail, err)
		return nil
	}

	if err := s.emailService.SendPasswordReset(ctx, user.Email, user.Name, rawToken); err != nil {
		log.Printf("auth: failed to send reset email to %s: %v", normalizedEmail, err)
	}

	return nil
}

// ResetPassword consumes a single-use password reset token to set a new
// password, then revokes every refresh token for the user so all existing
// sessions are forced to re-authenticate.
func (s *AuthService) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	if len(newPassword) < minPasswordLength {
		return ErrPasswordTooShort
	}

	tokenHash := hashToken(rawToken)
	resetToken, err := s.userRepo.FindPasswordResetTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrTokenInvalid
		}
		return fmt.Errorf("auth: failed to look up reset token: %w", err)
	}
	if resetToken.UsedAt != nil {
		return ErrTokenInvalid
	}
	if time.Now().UTC().After(resetToken.ExpiresAt) {
		return ErrTokenExpired
	}

	user, err := s.userRepo.FindByID(ctx, resetToken.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrTokenInvalid
		}
		return fmt.Errorf("auth: failed to look up user: %w", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return fmt.Errorf("auth: failed to hash new password: %w", err)
	}
	user.PasswordHash = string(hashedPassword)
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("auth: failed to update password: %w", err)
	}

	if err := s.userRepo.MarkPasswordResetTokenUsed(ctx, resetToken.ID); err != nil {
		return fmt.Errorf("auth: failed to mark reset token used: %w", err)
	}

	if err := s.refreshTokenRepo.RevokeAllByUserID(ctx, user.ID); err != nil {
		return fmt.Errorf("auth: failed to revoke refresh tokens: %w", err)
	}

	return nil
}

// hashToken returns the SHA-256 hex digest of raw, used to store both refresh
// tokens and password reset tokens without ever persisting the raw value.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// generateSecureToken returns a random n-byte token, hex-encoded.
func generateSecureToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: failed to generate random token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (s *AuthService) isPlatformAdminEmail(email string) bool {
	for _, adminEmail := range s.cfg.PlatformAdminEmails {
		if strings.EqualFold(adminEmail, email) {
			return true
		}
	}
	return false
}
