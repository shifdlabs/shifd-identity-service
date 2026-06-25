package handler

import (
	"errors"
	"log"
	"net/http"

	"github.com/ShifdLabs/shifd-identity-service/service"
	"github.com/gin-gonic/gin"
)

// UserHandler is the HTTP layer for the authenticated /api/me/* endpoints
// (the caller's own profile and org memberships). Every method requires a
// valid Bearer JWT (enforced by RequireAuth in the router) and acts on the
// user identified by the token's "sub" claim — never an ID from the request.
type UserHandler struct {
	userService *service.UserService
}

func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

// ---------------------------------------------------------------------------
// Request payloads
// ---------------------------------------------------------------------------

// updateProfileRequest uses pointers so an omitted field (nil) is left
// unchanged, distinct from an explicit empty string (which clears phone).
type updateProfileRequest struct {
	Name  *string `json:"name"`
	Phone *string `json:"phone"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// GetMe handles GET /api/me.
func (h *UserHandler) GetMe(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	user, err := h.userService.GetProfile(c.Request.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "User not found")
		default:
			log.Printf("handler: get me error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": toUserResponse(user), "message": "success"})
}

// UpdateMe handles PATCH /api/me.
func (h *UserHandler) UpdateMe(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	var req updateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	user, err := h.userService.UpdateProfile(c.Request.Context(), userID, req.Name, req.Phone)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidName):
			respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		case errors.Is(err, service.ErrUserNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "User not found")
		default:
			log.Printf("handler: update me error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": toUserResponse(user), "message": "success"})
}

// ChangePassword handles PATCH /api/me/password.
func (h *UserHandler) ChangePassword(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	err := h.userService.ChangePassword(c.Request.Context(), userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			respondError(c, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Current password is incorrect")
		case errors.Is(err, service.ErrPasswordTooShort):
			respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		case errors.Is(err, service.ErrUserNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "User not found")
		default:
			log.Printf("handler: change password error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": nil, "message": "Password has been changed"})
}

// ListMyOrgs handles GET /api/me/orgs.
func (h *UserHandler) ListMyOrgs(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	orgs, err := h.userService.ListUserOrgs(c.Request.Context(), userID)
	if err != nil {
		log.Printf("handler: list my orgs error: %v", err)
		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": toUserOrgsResponse(orgs), "message": "success"})
}
