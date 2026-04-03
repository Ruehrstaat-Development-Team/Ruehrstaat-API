package auth

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestGetIdentityTokenSecret(t *testing.T) {
	t.Run("missing secret panics", func(t *testing.T) {
		assertPanicContains(t, "JWT_IDENTITY_SECRET is required", func() {
			t.Setenv("JWT_IDENTITY_SECRET", strings.Repeat("x", 32))
			if err := os.Unsetenv("JWT_IDENTITY_SECRET"); err != nil {
				t.Fatalf("failed to unset JWT_IDENTITY_SECRET: %v", err)
			}
			_ = getIdentityTokenSecret()
		})
	})

	t.Run("short secret panics", func(t *testing.T) {
		assertPanicContains(t, "at least 32 characters", func() {
			t.Setenv("JWT_IDENTITY_SECRET", "too-short")
			_ = getIdentityTokenSecret()
		})
	})

	t.Run("valid secret returned", func(t *testing.T) {
		expected := strings.Repeat("a", 32)
		t.Setenv("JWT_IDENTITY_SECRET", expected)
		if got := getIdentityTokenSecret(); got != expected {
			t.Fatalf("getIdentityTokenSecret() = %q, want %q", got, expected)
		}
	})
}

func TestGetRefreshTokenSecret(t *testing.T) {
	t.Run("missing secret panics", func(t *testing.T) {
		assertPanicContains(t, "JWT_REFRESH_SECRET is required", func() {
			t.Setenv("JWT_REFRESH_SECRET", strings.Repeat("x", 16))
			if err := os.Unsetenv("JWT_REFRESH_SECRET"); err != nil {
				t.Fatalf("failed to unset JWT_REFRESH_SECRET: %v", err)
			}
			_ = getRefreshTokenSecret()
		})
	})

	t.Run("short secret panics", func(t *testing.T) {
		assertPanicContains(t, "at least 16 characters", func() {
			t.Setenv("JWT_REFRESH_SECRET", "too-short")
			_ = getRefreshTokenSecret()
		})
	})

	t.Run("valid secret returned", func(t *testing.T) {
		expected := strings.Repeat("b", 16)
		t.Setenv("JWT_REFRESH_SECRET", expected)
		if got := getRefreshTokenSecret(); got != expected {
			t.Fatalf("getRefreshTokenSecret() = %q, want %q", got, expected)
		}
	})
}

func TestGeneratePairRejectsExpiredAbsoluteExpiration(t *testing.T) {
	expired := time.Now().Add(-time.Minute).Unix()
	pair, err := generatePair(uuid.New(), &expired)
	if err != ErrAbsoluteExpReached {
		t.Fatalf("generatePair() error = %v, want %v", err, ErrAbsoluteExpReached)
	}
	if pair != (TokenPair{}) {
		t.Fatalf("generatePair() pair = %+v, want empty token pair", pair)
	}
}

func TestGeneratePairCreatesSignedTokens(t *testing.T) {
	t.Setenv("JWT_IDENTITY_SECRET", strings.Repeat("i", 32))
	t.Setenv("JWT_REFRESH_SECRET", strings.Repeat("r", 16))

	userID := uuid.New()
	absoluteExpiration := time.Now().Add(2 * time.Hour).Unix()

	pair, err := generatePair(userID, &absoluteExpiration)
	if err != nil {
		t.Fatalf("generatePair() returned error: %v", err)
	}
	if pair.IdenityToken == "" || pair.RefreshToken == "" {
		t.Fatalf("generatePair() returned empty tokens: %+v", pair)
	}
	if pair.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("generatePair() returned past expiry: %d", pair.ExpiresAt)
	}

	identityClaims := parseTokenClaims(t, pair.IdenityToken, strings.Repeat("i", 32))
	if sub, _ := identityClaims["sub"].(string); sub != userID.String() {
		t.Fatalf("identity token subject = %v, want %s", identityClaims["sub"], userID)
	}

	refreshClaims := parseTokenClaims(t, pair.RefreshToken, strings.Repeat("r", 16))
	if sub, _ := refreshClaims["sub"].(string); sub != userID.String() {
		t.Fatalf("refresh token subject = %v, want %s", refreshClaims["sub"], userID)
	}
	refreshExp := int64(refreshClaims["exp"].(float64))
	if refreshExp != absoluteExpiration {
		t.Fatalf("refresh token exp = %d, want %d", refreshExp, absoluteExpiration)
	}
}

func TestGenerateIdentityTokenWithSessionIncludesSessionClaims(t *testing.T) {
	secret := strings.Repeat("s", 32)
	userID := uuid.New()
	sessionID := uuid.New()
	expiresAt := time.Now().Add(time.Hour).Unix()

	tokenString, jti, err := generateIdentityTokenWithSession(secret, userID.String(), sessionID, expiresAt)
	if err != nil {
		t.Fatalf("generateIdentityTokenWithSession() returned error: %v", err)
	}
	if jti == "" {
		t.Fatal("generateIdentityTokenWithSession() returned empty jti")
	}

	claims := parseTokenClaims(t, tokenString, secret)
	if got, _ := claims["sub"].(string); got != userID.String() {
		t.Fatalf("sub claim = %v, want %s", claims["sub"], userID)
	}
	if got, _ := claims["sid"].(string); got != sessionID.String() {
		t.Fatalf("sid claim = %v, want %s", claims["sid"], sessionID)
	}
	if got, _ := claims["jti"].(string); got != jti {
		t.Fatalf("jti claim = %v, want %s", claims["jti"], jti)
	}
}

func TestGenerateRefreshTokenWithSessionIncludesSessionClaims(t *testing.T) {
	secret := strings.Repeat("r", 32)
	userID := uuid.New()
	sessionID := uuid.New()
	expiresAt := time.Now().Add(time.Hour).Unix()

	tokenString, err := generateRefreshTokenWithSession(secret, userID.String(), sessionID, expiresAt)
	if err != nil {
		t.Fatalf("generateRefreshTokenWithSession() returned error: %v", err)
	}

	claims := parseTokenClaims(t, tokenString, secret)
	if got, _ := claims["sub"].(string); got != userID.String() {
		t.Fatalf("sub claim = %v, want %s", claims["sub"], userID)
	}
	if got, _ := claims["sid"].(string); got != sessionID.String() {
		t.Fatalf("sid claim = %v, want %s", claims["sid"], sessionID)
	}
	if got := int64(claims["exp"].(float64)); got != expiresAt {
		t.Fatalf("exp claim = %d, want %d", got, expiresAt)
	}
}

func assertPanicContains(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatalf("expected panic containing %q", want)
		}
		if !strings.Contains(fmt.Sprint(recovered), want) {
			t.Fatalf("panic = %v, want substring %q", recovered, want)
		}
	}()

	fn()
}

func parseTokenClaims(t *testing.T, tokenString string, secret string) jwt.MapClaims {
	t.Helper()
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if !token.Valid {
		t.Fatal("parsed token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("token claims type = %T, want jwt.MapClaims", token.Claims)
	}
	return claims
}
