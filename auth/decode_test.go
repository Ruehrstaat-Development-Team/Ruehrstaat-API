package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestDecodeTokenHandlesStructuredAudienceClaim(t *testing.T) {
	secret := "1234567890abcdef1234567890abcdef"
	tokenString := signedMapClaimsToken(t, secret, jwt.MapClaims{
		"aud": []string{"other.example", "ruehrstaat.org"},
		"sub": uuid.New().String(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	decoded, err := decodeToken(secret, tokenString, "ruehrstaat.org")
	if err != nil {
		t.Fatalf("decodeToken() error = %v, want nil", err)
	}
	if decoded == nil {
		t.Fatal("decodeToken() decoded = nil, want token")
	}
}

func TestDecodeTokenRejectsMalformedClaimTypes(t *testing.T) {
	secret := "1234567890abcdef1234567890abcdef"
	validSub := uuid.New().String()
	validSID := uuid.New().String()

	tests := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{name: "subject not string", claims: jwt.MapClaims{"aud": "ruehrstaat.org", "sub": 123, "exp": time.Now().Add(time.Hour).Unix()}},
		{name: "expiration not numeric", claims: jwt.MapClaims{"aud": "ruehrstaat.org", "sub": validSub, "exp": "later"}},
		{name: "sid not string", claims: jwt.MapClaims{"aud": "ruehrstaat.org", "sub": validSub, "exp": time.Now().Add(time.Hour).Unix(), "sid": 123}},
		{name: "sid invalid uuid", claims: jwt.MapClaims{"aud": "ruehrstaat.org", "sub": validSub, "exp": time.Now().Add(time.Hour).Unix(), "sid": "not-a-uuid"}},
		{name: "jti not string", claims: jwt.MapClaims{"aud": "ruehrstaat.org", "sub": validSub, "exp": time.Now().Add(time.Hour).Unix(), "sid": validSID, "jti": 123}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := signedMapClaimsToken(t, secret, tt.claims)

			decoded, err := decodeToken(secret, tokenString, "ruehrstaat.org")
			if err != ErrInvalidToken {
				t.Fatalf("decodeToken() error = %v, want %v", err, ErrInvalidToken)
			}
			if decoded != nil {
				t.Fatalf("decodeToken() decoded = %+v, want nil", decoded)
			}
		})
	}
}

func signedMapClaimsToken(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	return tokenString
}
