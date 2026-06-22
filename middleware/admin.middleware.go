package middleware

import (
	"errors"
	"log"
	"net/http"

	"github.com/ShifdLabs/shifd-identity-service/repository"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RequireAdmin returns middleware that checks the authenticated user's
// is_platform_admin flag directly from the DB on every request — never from
// the JWT claims — per CLAUDE.md security rule #8. Must run after
// RequireAuth, which is what populates the claims this reads.
func RequireAdmin(userRepo *repository.UserRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := GetClaims(c)
		if claims == nil {
			respondForbidden(c)
			return
		}

		sub, ok := claims["sub"].(string)
		if !ok {
			respondForbidden(c)
			return
		}

		userID, err := uuid.Parse(sub)
		if err != nil {
			respondForbidden(c)
			return
		}

		isAdmin, err := userRepo.IsPlatformAdmin(c.Request.Context(), userID)
		if err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				log.Printf("middleware: failed to check platform admin status for %s: %v", userID, err)
			}
			respondForbidden(c)
			return
		}
		if !isAdmin {
			respondForbidden(c)
			return
		}

		c.Next()
	}
}

func respondForbidden(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error": "Platform admin access required",
		"code":  "FORBIDDEN",
	})
}
