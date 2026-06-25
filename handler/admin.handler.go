package handler

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/service"
	"github.com/gin-gonic/gin"
)

// AdminHandler is the HTTP layer for the /api/admin/* platform admin API.
// Every method requires the caller to be a platform admin, enforced by
// RequireAuth + RequireAdmin in the router (RequireAdmin re-checks
// users.is_platform_admin from the DB — never the JWT).
type AdminHandler struct {
	adminService        *service.AdminService
	subscriptionService *service.SubscriptionService
}

func NewAdminHandler(adminService *service.AdminService, subscriptionService *service.SubscriptionService) *AdminHandler {
	return &AdminHandler{adminService: adminService, subscriptionService: subscriptionService}
}

// ---------------------------------------------------------------------------
// Request payloads
// ---------------------------------------------------------------------------

type createOrgAdminRequest struct {
	Name       string `json:"name" binding:"required"`
	Slug       string `json:"slug" binding:"required"`
	OwnerEmail string `json:"owner_email" binding:"required,email"`
}

type createSubscriptionRequest struct {
	ProductID string    `json:"product_id" binding:"required"`
	Plan      string    `json:"plan" binding:"required"`
	ExpiresAt time.Time `json:"expires_at" binding:"required"`
	UserLimit *int      `json:"user_limit"`
}

type updateSubscriptionRequest struct {
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expires_at"`
	Plan      string     `json:"plan"`
}

type addMemberAdminRequest struct {
	Email string `json:"email" binding:"required,email"`
	Role  string `json:"role" binding:"required"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// ListOrgs handles GET /api/admin/orgs.
func (h *AdminHandler) ListOrgs(c *gin.Context) {
	page, limit := queryPagination(c, defaultPageLimit)

	orgs, total, err := h.adminService.ListOrgs(c.Request.Context(), page, limit)
	if err != nil {
		log.Printf("handler: admin list orgs error: %v", err)
		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":    paginatedResponse(toOrganizationsResponse(orgs), page, limit, total),
		"message": "success",
	})
}

// CreateOrg handles POST /api/admin/orgs.
func (h *AdminHandler) CreateOrg(c *gin.Context) {
	var req createOrgAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	org, err := h.adminService.CreateOrgForOwner(c.Request.Context(), req.Name, req.Slug, req.OwnerEmail)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "No user found with that owner_email")
		case errors.Is(err, service.ErrInvalidSlug):
			respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		case errors.Is(err, service.ErrSlugAlreadyExists):
			respondError(c, http.StatusConflict, "SLUG_ALREADY_EXISTS", err.Error())
		default:
			log.Printf("handler: admin create org error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": toOrganizationResponse(org), "message": "success"})
}

// GetOrg handles GET /api/admin/orgs/:org_id.
func (h *AdminHandler) GetOrg(c *gin.Context) {
	orgID, ok := pathUUID(c, "org_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid org_id")
		return
	}

	detail, err := h.adminService.GetOrgDetail(c.Request.Context(), orgID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrOrgNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "Organization not found")
		default:
			log.Printf("handler: admin get org error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"org":           toOrganizationResponse(detail.Org),
			"members":       toOrgMembersResponse(detail.Members),
			"subscriptions": toSubscriptionsResponse(detail.Subscriptions),
		},
		"message": "success",
	})
}

// AddMember handles POST /api/admin/orgs/:org_id/members.
func (h *AdminHandler) AddMember(c *gin.Context) {
	orgID, ok := pathUUID(c, "org_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid org_id")
		return
	}

	var req addMemberAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	membership, err := h.adminService.AddMember(c.Request.Context(), orgID, req.Email, req.Role)
	if err != nil {
		var limitErr *service.UserLimitReachedError
		switch {
		case errors.As(err, &limitErr):
			respondUserLimitReached(c, limitErr)
		case errors.Is(err, service.ErrNoActiveSubscription):
			respondError(c, http.StatusForbidden, "SUBSCRIPTION_INACTIVE", "No active subscription found")
		case errors.Is(err, service.ErrInvalidRole):
			respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		case errors.Is(err, service.ErrUserNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "User with this email not found in SIS")
		case errors.Is(err, service.ErrOrgNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "Organization not found")
		case errors.Is(err, service.ErrAlreadyMember):
			respondError(c, http.StatusConflict, "ALREADY_MEMBER", err.Error())
		default:
			log.Printf("handler: admin add member error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": toMembershipResponse(membership), "message": "success"})
}

// CreateSubscription handles POST /api/admin/orgs/:org_id/subscriptions.
func (h *AdminHandler) CreateSubscription(c *gin.Context) {
	orgID, ok := pathUUID(c, "org_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid org_id")
		return
	}

	var req createSubscriptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	sub, err := h.subscriptionService.CreateSubscription(c.Request.Context(), orgID, req.ProductID, req.Plan, req.ExpiresAt, req.UserLimit)
	if err != nil {
		log.Printf("handler: admin create subscription error: %v", err)
		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": toSubscriptionResponse(*sub), "message": "success"})
}

// UpdateSubscription handles PATCH /api/admin/orgs/:org_id/subscriptions/:sub_id.
func (h *AdminHandler) UpdateSubscription(c *gin.Context) {
	subID, ok := pathUUID(c, "sub_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid sub_id")
		return
	}

	var req updateSubscriptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	var expiresAt time.Time
	if req.ExpiresAt != nil {
		expiresAt = *req.ExpiresAt
	}

	sub, err := h.subscriptionService.UpdateSubscription(c.Request.Context(), subID, req.Status, expiresAt, req.Plan)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrSubscriptionNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "Subscription not found")
		case errors.Is(err, service.ErrInvalidSubscriptionStatus):
			respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		default:
			log.Printf("handler: admin update subscription error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": toSubscriptionResponse(*sub), "message": "success"})
}

// ListUsers handles GET /api/admin/users.
func (h *AdminHandler) ListUsers(c *gin.Context) {
	page, limit := queryPagination(c, defaultPageLimit)
	emailSearch := c.Query("email")

	users, total, err := h.adminService.ListUsers(c.Request.Context(), page, limit, emailSearch)
	if err != nil {
		log.Printf("handler: admin list users error: %v", err)
		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":    paginatedResponse(toUsersResponse(users), page, limit, total),
		"message": "success",
	})
}

// ForceLogout handles POST /api/admin/users/:uid/force-logout.
func (h *AdminHandler) ForceLogout(c *gin.Context) {
	userID, ok := pathUUID(c, "uid")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid user id")
		return
	}

	if err := h.adminService.ForceLogout(c.Request.Context(), userID); err != nil {
		log.Printf("handler: admin force logout error: %v", err)
		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": nil, "message": "all sessions revoked"})
}
