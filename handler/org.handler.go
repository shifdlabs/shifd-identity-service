package handler

import (
	"errors"
	"log"
	"net/http"

	"github.com/ShifdLabs/shifd-identity-service/service"
	"github.com/gin-gonic/gin"
)

// OrgHandler is the HTTP layer for the authenticated /api/orgs/* endpoints.
// Every method requires a valid Bearer JWT (enforced by RequireAuth in the
// router); org-role checks (owner/admin/member) happen in OrgService.
type OrgHandler struct {
	orgService          *service.OrgService
	subscriptionService *service.SubscriptionService
}

func NewOrgHandler(orgService *service.OrgService, subscriptionService *service.SubscriptionService) *OrgHandler {
	return &OrgHandler{orgService: orgService, subscriptionService: subscriptionService}
}

// ---------------------------------------------------------------------------
// Request payloads
// ---------------------------------------------------------------------------

type createOrgRequest struct {
	Name string `json:"name" binding:"required"`
	Slug string `json:"slug" binding:"required"`
}

type inviteMemberRequest struct {
	Email string `json:"email" binding:"required,email"`
	Role  string `json:"role"`
}

type updateMemberRequest struct {
	Role   string `json:"role"`
	Status string `json:"status"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// CreateOrg handles POST /api/orgs.
func (h *OrgHandler) CreateOrg(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	var req createOrgRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	org, err := h.orgService.CreateOrg(c.Request.Context(), userID, req.Name, req.Slug)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidSlug):
			respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		case errors.Is(err, service.ErrSlugAlreadyExists):
			respondError(c, http.StatusConflict, "SLUG_ALREADY_EXISTS", err.Error())
		default:
			log.Printf("handler: create org error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": toOrganizationResponse(org), "message": "success"})
}

// GetOrg handles GET /api/orgs/:org_id.
func (h *OrgHandler) GetOrg(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}
	orgID, ok := pathUUID(c, "org_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid org_id")
		return
	}

	detail, err := h.orgService.GetOrgByID(c.Request.Context(), orgID, userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			respondError(c, http.StatusForbidden, "FORBIDDEN", "You do not have access to this organization")
		case errors.Is(err, service.ErrOrgNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "Organization not found")
		default:
			log.Printf("handler: get org error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": toOrgDetailResponse(detail), "message": "success"})
}

// InviteMember handles POST /api/orgs/:org_id/members.
func (h *OrgHandler) InviteMember(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}
	orgID, ok := pathUUID(c, "org_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid org_id")
		return
	}

	var req inviteMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	membership, err := h.orgService.InviteMember(c.Request.Context(), orgID, userID, req.Email, req.Role)
	if err != nil {
		var limitErr *service.UserLimitReachedError
		switch {
		case errors.As(err, &limitErr):
			respondUserLimitReached(c, limitErr)
		case errors.Is(err, service.ErrNoActiveSubscription):
			respondError(c, http.StatusForbidden, "SUBSCRIPTION_INACTIVE", "No active subscription found")
		case errors.Is(err, service.ErrInvalidRole):
			respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		case errors.Is(err, service.ErrForbidden), errors.Is(err, service.ErrInsufficientPermissions):
			respondError(c, http.StatusForbidden, "FORBIDDEN", err.Error())
		case errors.Is(err, service.ErrUserNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "User dengan email ini belum terdaftar di SIS. Minta mereka mendaftar terlebih dahulu.")
		case errors.Is(err, service.ErrAlreadyMember):
			respondError(c, http.StatusConflict, "ALREADY_MEMBER", "User ini sudah menjadi member aktif di organisasi ini.")
		case errors.Is(err, service.ErrOrgNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "Organization not found")
		default:
			log.Printf("handler: invite member error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": toMembershipResponse(membership), "message": "success"})
}

// AcceptInvite handles POST /api/orgs/:org_id/members/accept.
func (h *OrgHandler) AcceptInvite(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}
	orgID, ok := pathUUID(c, "org_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid org_id")
		return
	}

	err := h.orgService.AcceptInvite(c.Request.Context(), userID, orgID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInviteNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "No pending invite found")
		case errors.Is(err, service.ErrInviteExpired):
			respondError(c, http.StatusUnauthorized, "TOKEN_EXPIRED", "Invite has expired")
		default:
			log.Printf("handler: accept invite error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": nil, "message": "success"})
}

// ListMembers handles GET /api/orgs/:org_id/members.
func (h *OrgHandler) ListMembers(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}
	orgID, ok := pathUUID(c, "org_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid org_id")
		return
	}

	members, err := h.orgService.ListMembers(c.Request.Context(), orgID, userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			respondError(c, http.StatusForbidden, "FORBIDDEN", "You do not have access to this organization")
		default:
			log.Printf("handler: list members error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": toOrgMembersResponse(members), "message": "success"})
}

// UpdateMember handles PATCH /api/orgs/:org_id/members/:user_id.
func (h *OrgHandler) UpdateMember(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}
	orgID, ok := pathUUID(c, "org_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid org_id")
		return
	}
	targetUserID, ok := pathUUID(c, "user_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid user_id")
		return
	}

	var req updateMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	err := h.orgService.UpdateMember(c.Request.Context(), orgID, userID, targetUserID, req.Role, req.Status)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden), errors.Is(err, service.ErrInsufficientPermissions), errors.Is(err, service.ErrCannotModifyOwner):
			respondError(c, http.StatusForbidden, "FORBIDDEN", err.Error())
		case errors.Is(err, service.ErrInvalidRole), errors.Is(err, service.ErrInvalidStatus):
			respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		case errors.Is(err, service.ErrMembershipNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "Member not found")
		default:
			log.Printf("handler: update member error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": nil, "message": "success"})
}

// RemoveMember handles DELETE /api/orgs/:org_id/members/:user_id.
func (h *OrgHandler) RemoveMember(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}
	orgID, ok := pathUUID(c, "org_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid org_id")
		return
	}
	targetUserID, ok := pathUUID(c, "user_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid user_id")
		return
	}

	err := h.orgService.RemoveMember(c.Request.Context(), orgID, userID, targetUserID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden), errors.Is(err, service.ErrInsufficientPermissions), errors.Is(err, service.ErrCannotRemoveOwner):
			respondError(c, http.StatusForbidden, "FORBIDDEN", err.Error())
		case errors.Is(err, service.ErrMembershipNotFound):
			respondError(c, http.StatusNotFound, "NOT_FOUND", "Member not found")
		default:
			log.Printf("handler: remove member error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": nil, "message": "success"})
}

// ListSubscriptions handles GET /api/orgs/:org_id/subscriptions.
func (h *OrgHandler) ListSubscriptions(c *gin.Context) {
	userID, ok := claimUserID(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}
	orgID, ok := pathUUID(c, "org_id")
	if !ok {
		respondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid org_id")
		return
	}

	if err := h.orgService.VerifyActiveMembership(c.Request.Context(), userID, orgID); err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			respondError(c, http.StatusForbidden, "FORBIDDEN", "You do not have access to this organization")
		default:
			log.Printf("handler: list subscriptions error: %v", err)
			respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		}
		return
	}

	subs, err := h.subscriptionService.ListByOrg(c.Request.Context(), orgID)
	if err != nil {
		log.Printf("handler: list subscriptions error: %v", err)
		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong")
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": toSubscriptionsResponse(subs), "message": "success"})
}
