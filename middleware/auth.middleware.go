package middleware

import (
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/ShifdLabs/shifd-identity-service/pkg/jwtutil"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// claimsContextKey is the Gin context key under which parsed JWT claims are
// stored by RequireAuth and retrieved by GetClaims.
const claimsContextKey = "claims"

// RequireAuth returns middleware that validates the Bearer JWT in the
// Authorization header using the RSA public key. On success the parsed claims
// are stored in the Gin context; on any failure it aborts with 401.
func RequireAuth(publicKey *rsa.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
		if authHeader == "" {
			respondUnauthorized(c)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			respondUnauthorized(c)
			return
		}

		tokenString := strings.TrimSpace(parts[1])
		if tokenString == "" {
			respondUnauthorized(c)
			return
		}

		claims, err := jwtutil.ParseToken(tokenString, publicKey)
		if err != nil {
			respondUnauthorized(c)
			return
		}

		c.Set(claimsContextKey, claims)
		c.Next()
	}
}

// GetClaims returns the JWT claims stored by RequireAuth, or nil if the request
// did not pass through RequireAuth (or claims are absent/wrong type).
func GetClaims(c *gin.Context) jwt.MapClaims {
	value, exists := c.Get(claimsContextKey)
	if !exists {
		return nil
	}
	claims, ok := value.(jwt.MapClaims)
	if !ok {
		return nil
	}
	return claims
}

func respondUnauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error": "Authentication required",
		"code":  "UNAUTHORIZED",
	})
}
