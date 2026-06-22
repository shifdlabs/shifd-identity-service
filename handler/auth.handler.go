package handler

import (
	"errors"
	"log"
	"net/http"

	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/ShifdLabs/shifd-identity-service/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthHandler is the HTTP layer for the /api/auth/* endpoints. It only parses
// requests, delegates to AuthService, and writes responses — no business logic.
type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// ---------------------------------------------------------------------------
// Request payloads
// ---------------------------------------------------------------------------

type registerRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Phone    string `json:"phone"`
}

type loginRequest struct {
	Email      string `json:"email" binding:"required,email"`
	Password   string `json:"password" binding:"required"`
	OrgID      string `json:"org_id"`
	DeviceInfo string `json:"device_info"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type forgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type resetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// Register handles POST /api/auth/register.
func (h *AuthHandler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	user, err := h.authService.Register(c.Request.Context(), req.Email, req.Password, req.Name, req.Phone)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrEmailAlreadyExists):
			respondError(c, http.StatusConflict, "EMAIL_ALREADY_EXISTS", "An account with that email already exists")
		case errors.Is(err, service.ErrInvalidEmail), errors.Is(err, service.ErrPasswordTooShort):
			// These sentinels carry safe, user-facing validation messages.
			respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		default:
			log.Printf("handler: register error for %s: %v", req.Email, err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": toUserResponse(user), "message": "success"})
}

// Login handles POST /api/auth/login.
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	var orgID *uuid.UUID
	if req.OrgID != "" {
		parsed, err := uuid.Parse(req.OrgID)
		if err != nil {
			respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid org_id")
			return
		}
		orgID = &parsed
	}

	result, err := h.authService.Login(c.Request.Context(), req.Email, req.Password, orgID, req.DeviceInfo)
	if err != nil {
		var lockedErr *service.AccountLockedError
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			respondError(c, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password")
		case errors.As(err, &lockedErr):
			respondError(c, http.StatusForbidden, "ACCOUNT_LOCKED", "Account is locked due to too many failed login attempts")
		case errors.Is(err, service.ErrForbidden):
			respondError(c, http.StatusForbidden, "FORBIDDEN", "You do not have access to the requested organization")
		default:
			log.Printf("handler: login error for %s: %v", req.Email, err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"access_token":  result.AccessToken,
			"refresh_token": result.RefreshToken,
			"user":          toUserResponse(result.User),
			"org":           toOrgResponse(result.Org),
		},
		"message": "success",
	})
}

// Refresh handles POST /api/auth/refresh.
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	accessToken, err := h.authService.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTokenExpired):
			respondError(c, http.StatusUnauthorized, "TOKEN_EXPIRED", "Refresh token has expired")
		case errors.Is(err, service.ErrTokenInvalid):
			respondError(c, http.StatusUnauthorized, "TOKEN_INVALID", "Refresh token is invalid")
		default:
			log.Printf("handler: refresh error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": gin.H{"access_token": accessToken}, "message": "success"})
}

// Logout handles POST /api/auth/logout. Revoking an unknown or already-revoked
// token is not an error (the service is idempotent), so success is the norm.
func (h *AuthHandler) Logout(c *gin.Context) {
	var req logoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	if err := h.authService.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		log.Printf("handler: logout error: %v", err)
		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": nil, "message": "logged out"})
}

// ForgotPassword handles POST /api/auth/forgot-password. It always responds 200
// regardless of whether the email exists, to prevent account enumeration.
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req forgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	// The service swallows internal failures (logging them) and always returns
	// nil; we ignore the result and respond identically in every case.
	_ = h.authService.ForgotPassword(c.Request.Context(), req.Email)

	c.JSON(http.StatusOK, gin.H{
		"data":    nil,
		"message": "If an account exists for that email, a password reset link has been sent",
	})
}

// ResetPassword handles POST /api/auth/reset-password.
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req resetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	err := h.authService.ResetPassword(c.Request.Context(), req.Token, req.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrPasswordTooShort):
			respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		case errors.Is(err, service.ErrTokenExpired):
			respondError(c, http.StatusUnauthorized, "TOKEN_EXPIRED", "Reset token has expired")
		case errors.Is(err, service.ErrTokenInvalid):
			respondError(c, http.StatusUnauthorized, "TOKEN_INVALID", "Reset token is invalid")
		default:
			log.Printf("handler: reset-password error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": nil, "message": "Password has been reset"})
}

// ---------------------------------------------------------------------------
// Shared response helpers (used across the handler package)
// ---------------------------------------------------------------------------

// respondError writes the standard SIS error envelope.
func respondError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": message, "code": code})
}

// toUserResponse maps a User to a safe public shape. It deliberately omits
// password_hash and other internal fields so they can never leak in responses.
func toUserResponse(u *model.User) gin.H {
	if u == nil {
		return nil
	}
	return gin.H{
		"id":                u.ID,
		"email":             u.Email,
		"name":              u.Name,
		"phone":             u.Phone,
		"is_platform_admin": u.IsPlatformAdmin,
		"email_verified_at": u.EmailVerifiedAt,
		"created_at":        u.CreatedAt,
		"updated_at":        u.UpdatedAt,
	}
}

// toOrgResponse maps the org membership selected as the session's org context
// into the response. Returns nil when the user has no active membership.
func toOrgResponse(m *model.OrgMembership) gin.H {
	if m == nil {
		return nil
	}
	return gin.H{
		"org_id": m.OrgID,
		"role":   m.Role,
		"status": m.Status,
	}
}
