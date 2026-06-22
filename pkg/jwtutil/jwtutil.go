// Package jwtutil signs and parses RS256 JWTs and builds the JWKS document for SIS.
package jwtutil

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Keys holds the RSA key pair and key ID used to sign and verify JWTs.
type Keys struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
	KeyID   string
}

// LoadPrivateKey decodes a base64-encoded PEM block and parses it into an RSA private key.
// It accepts both PKCS1 ("openssl genrsa" output) and PKCS8 encoded keys.
func LoadPrivateKey(base64PEM string) (*rsa.PrivateKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(base64PEM)
	if err != nil {
		return nil, fmt.Errorf("jwtutil: failed to base64-decode private key: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("jwtutil: failed to decode PEM block from private key")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwtutil: failed to parse private key: %w", err)
	}

	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("jwtutil: private key is not an RSA key")
	}
	return rsaKey, nil
}

// LoadPublicKey decodes a base64-encoded PEM block and parses it into an RSA public key.
// It accepts both PKIX ("openssl rsa -pubout" output) and PKCS1 encoded keys.
func LoadPublicKey(base64PEM string) (*rsa.PublicKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(base64PEM)
	if err != nil {
		return nil, fmt.Errorf("jwtutil: failed to base64-decode public key: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("jwtutil: failed to decode PEM block from public key")
	}

	if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("jwtutil: public key is not an RSA key")
		}
		return rsaKey, nil
	}

	rsaKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwtutil: failed to parse public key: %w", err)
	}
	return rsaKey, nil
}

// GenerateAccessToken signs an RS256 JWT containing claims plus the standard
// registered claims (iss, iat, exp, jti) from the CLAUDE.md JWT Claims Structure.
// claims is expected to carry the caller-supplied fields: sub, email, name,
// org_id, org_role, products.
func GenerateAccessToken(privateKey *rsa.PrivateKey, keyID string, issuer string, expiry time.Duration, claims map[string]interface{}) (string, error) {
	if privateKey == nil {
		return "", errors.New("jwtutil: private key is nil")
	}

	now := time.Now().UTC()
	mapClaims := jwt.MapClaims{}
	for k, v := range claims {
		mapClaims[k] = v
	}
	mapClaims["iss"] = issuer
	mapClaims["iat"] = jwt.NewNumericDate(now)
	mapClaims["exp"] = jwt.NewNumericDate(now.Add(expiry))
	mapClaims["jti"] = uuid.NewString()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = keyID

	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("jwtutil: failed to sign token: %w", err)
	}
	return signed, nil
}

// ParseToken validates the RS256 signature and standard claims (including
// expiry) of tokenString and returns its claims.
func ParseToken(tokenString string, publicKey *rsa.PublicKey) (jwt.MapClaims, error) {
	if publicKey == nil {
		return nil, errors.New("jwtutil: public key is nil")
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("jwtutil: unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("jwtutil: failed to parse token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("jwtutil: token is invalid")
	}
	return claims, nil
}

// BuildJWKS returns the JWKS document (RFC 7517) for publicKey, keyed by keyID,
// in the shape required by the SIS /.well-known/jwks.json endpoint.
func BuildJWKS(publicKey *rsa.PublicKey, keyID string) (map[string]interface{}, error) {
	if publicKey == nil {
		return nil, errors.New("jwtutil: public key is nil")
	}

	key, err := jwk.FromRaw(publicKey)
	if err != nil {
		return nil, fmt.Errorf("jwtutil: failed to build JWK: %w", err)
	}
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("jwtutil: failed to set kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, fmt.Errorf("jwtutil: failed to set alg: %w", err)
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("jwtutil: failed to set use: %w", err)
	}

	// Marshal through the JWK's own encoder so RSA fields (n, e) are
	// base64url-encoded per RFC 7518, then decode into a generic map.
	raw, err := json.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("jwtutil: failed to marshal JWK: %w", err)
	}

	var keyMap map[string]interface{}
	if err := json.Unmarshal(raw, &keyMap); err != nil {
		return nil, fmt.Errorf("jwtutil: failed to decode JWK: %w", err)
	}

	return map[string]interface{}{
		"keys": []map[string]interface{}{keyMap},
	}, nil
}
