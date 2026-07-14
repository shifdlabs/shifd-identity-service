package middleware

import (
	"crypto/rsa"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/pkg/jwtutil"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

const (
	// limiterTTL is how long an idle per-IP limiter is retained before the
	// sweeper evicts it, bounding memory growth from one-off IPs.
	limiterTTL = 15 * time.Minute
	// limiterSweepInterval is how often the sweeper scans for idle limiters.
	limiterSweepInterval = 5 * time.Minute
)

// limiterEntry is one per-IP token bucket plus the last time it was accessed
// (unix nanoseconds, updated atomically) so the sweeper can evict idle IPs.
type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64
}

// limiterStore holds one *rate.Limiter per client IP and runs a background
// sweeper that evicts limiters idle longer than limiterTTL, so memory no longer
// grows unbounded with the number of distinct IPs seen.
type limiterStore struct {
	limit rate.Limit
	burst int
	m     sync.Map // map[string]*limiterEntry
}

func newLimiterStore(limit rate.Limit, burst int) *limiterStore {
	s := &limiterStore{limit: limit, burst: burst}
	go s.sweepLoop()
	return s
}

func (s *limiterStore) get(ip string) *rate.Limiter {
	now := time.Now().UnixNano()
	if v, ok := s.m.Load(ip); ok {
		entry := v.(*limiterEntry)
		entry.lastSeen.Store(now)
		return entry.limiter
	}
	entry := &limiterEntry{limiter: rate.NewLimiter(s.limit, s.burst)}
	entry.lastSeen.Store(now)
	actual, _ := s.m.LoadOrStore(ip, entry)
	stored := actual.(*limiterEntry)
	stored.lastSeen.Store(now)
	return stored.limiter
}

func (s *limiterStore) sweepLoop() {
	ticker := time.NewTicker(limiterSweepInterval)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-limiterTTL).UnixNano()
		s.m.Range(func(key, value any) bool {
			if value.(*limiterEntry).lastSeen.Load() < cutoff {
				s.m.Delete(key)
			}
			return true
		})
	}
}

// RateLimitPerMinute returns middleware that limits each client IP to
// requestsPerMinute requests per minute (token-bucket, burst == the per-minute
// budget). One *rate.Limiter is kept per IP; idle limiters are evicted by a
// background sweeper (see limiterStore) so memory stays bounded.
func RateLimitPerMinute(requestsPerMinute int) gin.HandlerFunc {
	// Guard against a misconfigured (zero/negative) limit, which would panic on
	// the rate.Every division below — treat it as "no limiting".
	if requestsPerMinute <= 0 {
		return func(c *gin.Context) { c.Next() }
	}

	store := newLimiterStore(rate.Every(time.Minute/time.Duration(requestsPerMinute)), requestsPerMinute)

	return func(c *gin.Context) {
		if !store.get(c.ClientIP()).Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests, please try again later",
				"code":  "RATE_LIMIT_EXCEEDED",
			})
			return
		}
		c.Next()
	}
}

// RateLimitRegisterPerMinute returns middleware for POST /api/auth/register
// that applies one of two per-IP limits depending on the caller:
//   - authenticatedPerMinute: the request carries a Bearer token whose RS256
//     signature verifies against publicKey and whose issuer matches (e.g. an
//     org admin doing a bulk import of new users)
//   - publicPerMinute: no Authorization header, or a token that fails
//     verification — treated as anonymous public registration
//
// The token must actually verify to unlock the higher limit. A missing,
// malformed, or invalid Authorization header always falls back to
// publicPerMinute, so the anti-abuse protection on public signup cannot be
// bypassed by spoofing the header with an arbitrary value.
func RateLimitRegisterPerMinute(publicPerMinute, authenticatedPerMinute int, publicKey *rsa.PublicKey, issuer string) gin.HandlerFunc {
	publicLimiter := RateLimitPerMinute(publicPerMinute)
	authenticatedLimiter := RateLimitPerMinute(authenticatedPerMinute)

	return func(c *gin.Context) {
		if hasValidBearerToken(c, publicKey, issuer) {
			authenticatedLimiter(c)
			return
		}
		publicLimiter(c)
	}
}

// hasValidBearerToken reports whether the request carries an Authorization
// header of the form "Bearer <token>" whose signature and issuer verify against
// publicKey/issuer. It does not abort the request on failure — callers decide
// what to do with an absent or invalid token.
func hasValidBearerToken(c *gin.Context, publicKey *rsa.PublicKey, issuer string) bool {
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	if authHeader == "" {
		return false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return false
	}

	tokenString := strings.TrimSpace(parts[1])
	if tokenString == "" {
		return false
	}

	_, err := jwtutil.ParseToken(tokenString, publicKey, issuer)
	return err == nil
}
