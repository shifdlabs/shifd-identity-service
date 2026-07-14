package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders returns middleware that sets conservative security response
// headers on every response. HSTS is only emitted when production is true,
// since it must not be sent over plain HTTP during local development.
func SecurityHeaders(production bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("X-XSS-Protection", "0")
		if production {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}
