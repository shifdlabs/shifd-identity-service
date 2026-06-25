package handler

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/ShifdLabs/shifd-identity-service/middleware"
	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/ShifdLabs/shifd-identity-service/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const defaultPageLimit = 20

// ---------------------------------------------------------------------------
// Request parsing helpers shared across handlers
// ---------------------------------------------------------------------------

// claimUserID extracts and parses the "sub" claim (the authenticated user's
// ID) from the JWT claims RequireAuth stored on the context. ok is false if
// claims are missing or sub is not a valid UUID — should not happen for a
// request that passed RequireAuth, but callers check it defensively.
func claimUserID(c *gin.Context) (uuid.UUID, bool) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		return uuid.Nil, false
	}
	sub, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil, false
	}
	userID, err := uuid.Parse(sub)
	if err != nil {
		return uuid.Nil, false
	}
	return userID, true
}

// pathUUID parses the named path parameter as a UUID.
func pathUUID(c *gin.Context, name string) (uuid.UUID, bool) {
	value, err := uuid.Parse(c.Param(name))
	if err != nil {
		return uuid.Nil, false
	}
	return value, true
}

// queryPagination parses page/limit query params, defaulting to 1/defaultLimit
// and falling back to the default for non-positive or unparseable values.
func queryPagination(c *gin.Context, defaultLimit int) (page, limit int) {
	page = 1
	if raw := c.Query("page"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			page = parsed
		}
	}
	limit = defaultLimit
	if raw := c.Query("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	return page, limit
}

// respondUserLimitReached writes the 403 response for *service.UserLimitReachedError,
// which carries current/limit fields beyond the standard {error, code} envelope.
func respondUserLimitReached(c *gin.Context, limitErr *service.UserLimitReachedError) {
	c.JSON(http.StatusForbidden, gin.H{
		"error": fmt.Sprintf(
			"User baru tidak dapat ditambahkan: kapasitas organisasi sudah penuh (%d/%d user). Upgrade plan untuk menambah kapasitas user.",
			limitErr.Current, limitErr.Limit,
		),
		"code":    "USER_LIMIT_REACHED",
		"current": limitErr.Current,
		"limit":   limitErr.Limit,
	})
}

// paginatedResponse wraps items in the standard {items, pagination} shape
// used by every paginated admin endpoint.
func paginatedResponse(items interface{}, page, limit int, total int64) gin.H {
	totalPages := int((total + int64(limit) - 1) / int64(limit))
	if totalPages < 1 {
		totalPages = 1
	}
	return gin.H{
		"items": items,
		"pagination": gin.H{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": totalPages,
		},
	}
}

// ---------------------------------------------------------------------------
// Response mappers shared across handlers
// ---------------------------------------------------------------------------

func toOrganizationResponse(org *model.Organization) gin.H {
	if org == nil {
		return nil
	}
	return gin.H{
		"id":         org.ID,
		"name":       org.Name,
		"slug":       org.Slug,
		"created_at": org.CreatedAt,
		"updated_at": org.UpdatedAt,
	}
}

func toOrganizationsResponse(orgs []model.Organization) []gin.H {
	result := make([]gin.H, 0, len(orgs))
	for _, org := range orgs {
		result = append(result, toOrganizationResponse(&org))
	}
	return result
}

func toOrgDetailResponse(detail *service.OrgDetail) gin.H {
	if detail == nil {
		return nil
	}
	return gin.H{
		"org":                  toOrganizationResponse(detail.Org),
		"member_count":         detail.MemberCount,
		"active_subscriptions": toSubscriptionsResponse(detail.ActiveSubscriptions),
	}
}

func toSubscriptionResponse(sub model.Subscription) gin.H {
	return gin.H{
		"id":         sub.ID,
		"org_id":     sub.OrgID,
		"product_id": sub.ProductID,
		"plan":       sub.Plan,
		"status":     sub.Status,
		"started_at": sub.StartedAt,
		"expires_at": sub.ExpiresAt,
		"user_limit": sub.UserLimit,
		"created_at": sub.CreatedAt,
		"updated_at": sub.UpdatedAt,
	}
}

func toSubscriptionsResponse(subs []model.Subscription) []gin.H {
	result := make([]gin.H, 0, len(subs))
	for _, sub := range subs {
		result = append(result, toSubscriptionResponse(sub))
	}
	return result
}

// toMembershipResponse maps a raw OrgMembership row (e.g. one just created)
// into the response shape, unlike toOrgMemberResponse which maps the
// user-joined view.
func toMembershipResponse(m *model.OrgMembership) gin.H {
	if m == nil {
		return nil
	}
	return gin.H{
		"id":         m.ID,
		"user_id":    m.UserID,
		"org_id":     m.OrgID,
		"role":       m.Role,
		"status":     m.Status,
		"invited_by": m.InvitedBy,
		"invited_at": m.InvitedAt,
		"joined_at":  m.JoinedAt,
		"created_at": m.CreatedAt,
	}
}

func toOrgMemberResponse(m service.OrgMember) gin.H {
	return gin.H{
		"user_id":    m.UserID,
		"email":      m.Email,
		"name":       m.Name,
		"role":       m.Role,
		"status":     m.Status,
		"invited_at": m.InvitedAt,
		"joined_at":  m.JoinedAt,
	}
}

func toOrgMembersResponse(members []service.OrgMember) []gin.H {
	result := make([]gin.H, 0, len(members))
	for _, m := range members {
		result = append(result, toOrgMemberResponse(m))
	}
	return result
}

func toUsersResponse(users []model.User) []gin.H {
	result := make([]gin.H, 0, len(users))
	for _, u := range users {
		result = append(result, toUserResponse(&u))
	}
	return result
}

func toUserOrgResponse(uo service.UserOrg) gin.H {
	return gin.H{
		"org":                  toOrganizationResponse(uo.Org),
		"role":                 uo.Role,
		"membership_status":    uo.MembershipStatus,
		"active_subscriptions": toSubscriptionsResponse(uo.ActiveSubscriptions),
	}
}

func toUserOrgsResponse(orgs []service.UserOrg) []gin.H {
	result := make([]gin.H, 0, len(orgs))
	for _, uo := range orgs {
		result = append(result, toUserOrgResponse(uo))
	}
	return result
}
