package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimitPerMinute returns middleware that limits each client IP to
// requestsPerMinute requests per minute (token-bucket, burst == the per-minute
// budget). One *rate.Limiter is kept per IP in a sync.Map.
//
// Note: limiters are never evicted, so memory grows with the number of distinct
// IPs seen. That is acceptable for the Phase 1 auth endpoints; a sweeper can be
// added later if needed.
func RateLimitPerMinute(requestsPerMinute int) gin.HandlerFunc {
	// Guard against a misconfigured (zero/negative) limit, which would panic on
	// the rate.Every division below — treat it as "no limiting".
	if requestsPerMinute <= 0 {
		return func(c *gin.Context) { c.Next() }
	}

	var limiters sync.Map // map[string]*rate.Limiter
	limit := rate.Every(time.Minute / time.Duration(requestsPerMinute))

	return func(c *gin.Context) {
		ip := c.ClientIP()

		value, ok := limiters.Load(ip)
		if !ok {
			value, _ = limiters.LoadOrStore(ip, rate.NewLimiter(limit, requestsPerMinute))
		}
		limiter := value.(*rate.Limiter)

		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests, please try again later",
				"code":  "RATE_LIMIT_EXCEEDED",
			})
			return
		}

		c.Next()
	}
}
