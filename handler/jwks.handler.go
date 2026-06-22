package handler

import (
	"crypto/rsa"
	"log"
	"net/http"

	"github.com/ShifdLabs/shifd-identity-service/pkg/jwtutil"
	"github.com/gin-gonic/gin"
)

// JWKSHandler serves the public RSA key as a JWK set so downstream services
// (e.g. Shifd Approval) can validate JWTs locally without calling SIS.
type JWKSHandler struct {
	publicKey *rsa.PublicKey
	keyID     string
}

func NewJWKSHandler(publicKey *rsa.PublicKey, keyID string) *JWKSHandler {
	return &JWKSHandler{publicKey: publicKey, keyID: keyID}
}

// JWKS handles GET /.well-known/jwks.json.
//
// The body is the raw RFC 7517 JWK set ({"keys": [...]}) — intentionally NOT
// wrapped in the standard {data, message} envelope, because consumers parse it
// as a standard JWKS document. The key is public and long-lived, so it is
// cached for 24h to match Approval's refresh cadence.
func (h *JWKSHandler) JWKS(c *gin.Context) {
	jwks, err := jwtutil.BuildJWKS(h.publicKey, h.keyID)
	if err != nil {
		log.Printf("handler: failed to build JWKS: %v", err)
		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to build key set")
		return
	}

	c.Header("Cache-Control", "public, max-age=86400")
	c.JSON(http.StatusOK, jwks)
}
