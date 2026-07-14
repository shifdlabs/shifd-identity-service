package jwtutil

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://auth.shifd.test"

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test RSA key: %v", err)
	}
	return key
}

func TestParseToken_RoundTrip(t *testing.T) {
	key := newTestKey(t)

	signed, err := GenerateAccessToken(key, "sis-key-v1", testIssuer, time.Hour, map[string]interface{}{
		"sub":   "user-123",
		"email": "user@company.com",
	})
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	claims, err := ParseToken(signed, &key.PublicKey, testIssuer)
	if err != nil {
		t.Fatalf("ParseToken: unexpected error: %v", err)
	}
	if claims["sub"] != "user-123" {
		t.Errorf("sub claim = %v, want user-123", claims["sub"])
	}
	if claims["iss"] != testIssuer {
		t.Errorf("iss claim = %v, want %s", claims["iss"], testIssuer)
	}
	if _, ok := claims["jti"]; !ok {
		t.Error("expected jti claim to be present")
	}
}

// TestParseToken_RejectsWrongIssuer covers S-12: the issuer must be validated.
func TestParseToken_RejectsWrongIssuer(t *testing.T) {
	key := newTestKey(t)
	signed, err := GenerateAccessToken(key, "sis-key-v1", "https://evil.example", time.Hour, map[string]interface{}{"sub": "u"})
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	if _, err := ParseToken(signed, &key.PublicKey, testIssuer); err == nil {
		t.Fatal("expected ParseToken to reject a token with a mismatched issuer")
	}
}

// TestParseToken_RejectsNoneAlg covers the "alg=none" algorithm-confusion attack.
func TestParseToken_RejectsNoneAlg(t *testing.T) {
	key := newTestKey(t)

	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "attacker",
		"iss": testIssuer,
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to sign none-alg token: %v", err)
	}

	if _, err := ParseToken(signed, &key.PublicKey, testIssuer); err == nil {
		t.Fatal("expected ParseToken to reject an alg=none token")
	}
}

// TestParseToken_RejectsHS256Confusion covers the classic RS256->HS256 confusion
// attack where the attacker signs an HMAC token using the public key as secret.
func TestParseToken_RejectsHS256Confusion(t *testing.T) {
	key := newTestKey(t)

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "attacker",
		"iss": testIssuer,
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	signed, err := tok.SignedString([]byte("public-key-bytes-as-hmac-secret"))
	if err != nil {
		t.Fatalf("failed to sign HS256 token: %v", err)
	}

	if _, err := ParseToken(signed, &key.PublicKey, testIssuer); err == nil {
		t.Fatal("expected ParseToken to reject an HS256-signed token")
	}
}

func TestParseToken_RejectsExpired(t *testing.T) {
	key := newTestKey(t)
	signed, err := GenerateAccessToken(key, "sis-key-v1", testIssuer, -time.Hour, map[string]interface{}{"sub": "u"})
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	if _, err := ParseToken(signed, &key.PublicKey, testIssuer); err == nil {
		t.Fatal("expected ParseToken to reject an expired token")
	}
}

func TestParseToken_RejectsWrongKey(t *testing.T) {
	signingKey := newTestKey(t)
	otherKey := newTestKey(t)

	signed, err := GenerateAccessToken(signingKey, "sis-key-v1", testIssuer, time.Hour, map[string]interface{}{"sub": "u"})
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	if _, err := ParseToken(signed, &otherKey.PublicKey, testIssuer); err == nil {
		t.Fatal("expected ParseToken to reject a token signed by a different key")
	}
}

func TestParseToken_NilKey(t *testing.T) {
	if _, err := ParseToken("anything", nil, testIssuer); err == nil {
		t.Fatal("expected ParseToken to error on a nil public key")
	}
}

func TestBuildJWKS(t *testing.T) {
	key := newTestKey(t)

	jwks, err := BuildJWKS(&key.PublicKey, "sis-key-v1")
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}

	keys, ok := jwks["keys"].([]map[string]interface{})
	if !ok || len(keys) != 1 {
		t.Fatalf("expected exactly one JWK in the set, got %#v", jwks["keys"])
	}

	jwk := keys[0]
	for _, field := range []string{"kty", "use", "alg", "kid", "n", "e"} {
		if _, ok := jwk[field]; !ok {
			t.Errorf("JWK missing required field %q", field)
		}
	}
	if jwk["kid"] != "sis-key-v1" {
		t.Errorf("kid = %v, want sis-key-v1", jwk["kid"])
	}
	if jwk["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", jwk["alg"])
	}
}

// TestParseToken_RejectsMissingExp: a validly signed token with no "exp" claim
// must be rejected (WithExpirationRequired), so expiry validation can never be
// skipped by omitting the claim.
func TestParseToken_RejectsMissingExp(t *testing.T) {
	key := newTestKey(t)

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "u",
		"iss": testIssuer,
	})
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	if _, err := ParseToken(signed, &key.PublicKey, testIssuer); err == nil {
		t.Fatal("expected ParseToken to reject a token without an exp claim")
	}
}
