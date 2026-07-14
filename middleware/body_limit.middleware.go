package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxRequestBodyBytes is the default cap for incoming request bodies (1 MiB).
// SIS only ever accepts small JSON payloads, so this comfortably bounds memory
// use while rejecting oversized bodies that could be used to exhaust memory.
const MaxRequestBodyBytes int64 = 1 << 20

// BodyLimit returns middleware that caps the size of the request body at
// maxBytes. Reads past the limit fail, and handlers using ShouldBindJSON will
// surface that as a 400 via their existing validation-error path.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}
