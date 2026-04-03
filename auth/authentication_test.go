package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"ruehrstaat-backend/db/entities"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestHasRecentBrowserSessionAuthTime(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		authTime time.Time
		want     bool
	}{
		{name: "zero auth time", authTime: time.Time{}, want: false},
		{name: "fresh auth time", authTime: now.Add(-(FreshBrowserSessionMaxAge - time.Minute)), want: true},
		{name: "stale auth time", authTime: now.Add(-(FreshBrowserSessionMaxAge + time.Second)), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRecentBrowserSessionAuthTime(tt.authTime, now); got != tt.want {
				t.Fatalf("hasRecentBrowserSessionAuthTime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRateLimitIdentifierWithClientIP(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		clientIP   string
		want       string
	}{
		{name: "with ipv4", identifier: "user@example.com", clientIP: "203.0.113.10", want: "user@example.com|ip:203.0.113.10"},
		{name: "trims and normalizes ipv6", identifier: "user@example.com", clientIP: " 2001:db8::1 ", want: "user@example.com|ip:2001:db8::1"},
		{name: "falls back when ip missing", identifier: "user@example.com", clientIP: "", want: "user@example.com|ip:unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rateLimitIdentifierWithClientIP(tt.identifier, tt.clientIP); got != tt.want {
				t.Fatalf("rateLimitIdentifierWithClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeBearerIdentityTokenRejectsLegacyTokenWithoutSessionID(t *testing.T) {
	t.Setenv("JWT_IDENTITY_SECRET", strings.Repeat("i", 32))

	legacyToken, err := generateToken(getIdentityTokenSecret(), uuid.New().String(), time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatalf("generateToken() returned error: %v", err)
	}

	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+legacyToken)
	ctx.Request = req

	decoded, decodeErr := decodeBearerIdentityToken(ctx)
	if decodeErr != ErrInvalidToken {
		t.Fatalf("decodeBearerIdentityToken() error = %v, want %v", decodeErr, ErrInvalidToken)
	}
	if decoded != nil {
		t.Fatalf("decodeBearerIdentityToken() decoded = %+v, want nil", decoded)
	}
}

func TestPasswordResetRequestRateLimitCountsRequestsWithoutReset(t *testing.T) {
	cleanup := setupAuthTestRedis(t)
	defer cleanup()

	ctx := context.Background()
	email := "user@example.com"
	clientIP := "203.0.113.10"

	for i := 0; i < PasswordResetRequestMaxAttempts; i++ {
		if err := CheckAndIncrementPasswordResetRequestRateLimit(ctx, email, clientIP); err != nil {
			t.Fatalf("request %d error = %v, want nil", i+1, err)
		}
	}

	if err := CheckAndIncrementPasswordResetRequestRateLimit(ctx, email, clientIP); err != ErrPasswordResetRateLimited {
		t.Fatalf("CheckAndIncrementPasswordResetRequestRateLimit() after max requests = %v, want %v", err, ErrPasswordResetRateLimited)
	}
}

func TestPasswordResetRequestRateLimitNormalizesEmail(t *testing.T) {
	cleanup := setupAuthTestRedis(t)
	defer cleanup()

	ctx := context.Background()
	clientIP := "203.0.113.10"
	variants := []string{
		"User@Example.com",
		" user@example.com ",
		"USER@example.com",
		" user@EXAMPLE.com ",
	}

	for i := 0; i < len(variants)-1; i++ {
		if err := CheckAndIncrementPasswordResetRequestRateLimit(ctx, variants[i], clientIP); err != nil {
			t.Fatalf("variant %d error = %v, want nil", i+1, err)
		}
	}

	if err := CheckAndIncrementPasswordResetRequestRateLimit(ctx, variants[len(variants)-1], clientIP); err != ErrPasswordResetRateLimited {
		t.Fatalf("CheckAndIncrementPasswordResetRequestRateLimit() with normalized variant = %v, want %v", err, ErrPasswordResetRateLimited)
	}
}

func TestLoginOtpPasswordBindingMatches(t *testing.T) {
	tests := []struct {
		name         string
		user         *entities.User
		passwordHash string
		want         bool
	}{
		{name: "matching hash", user: &entities.User{Password: "hash-1"}, passwordHash: "hash-1", want: true},
		{name: "missing hash", user: &entities.User{Password: "hash-1"}, passwordHash: "", want: false},
		{name: "changed password", user: &entities.User{Password: "hash-2"}, passwordHash: "hash-1", want: false},
		{name: "missing user", user: nil, passwordHash: "hash-1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loginOtpPasswordBindingMatches(tt.user, tt.passwordHash); got != tt.want {
				t.Fatalf("loginOtpPasswordBindingMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldRevokeAllOnRefreshMismatch(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		session *entities.RefreshToken
		want    bool
	}{
		{name: "missing session", session: nil, want: false},
		{name: "already revoked session", session: &entities.RefreshToken{IsRevoked: true, ExpiresAt: now.Add(time.Hour)}, want: false},
		{name: "expired session", session: &entities.RefreshToken{ExpiresAt: now.Add(-time.Second)}, want: false},
		{name: "missing last used at", session: &entities.RefreshToken{ExpiresAt: now.Add(time.Hour)}, want: true},
		{name: "recent rotation race", session: &entities.RefreshToken{ExpiresAt: now.Add(time.Hour), LastUsedAt: timePtr(now.Add(-(RefreshReplayRaceGracePeriod - time.Second)))}, want: false},
		{name: "stale mismatch", session: &entities.RefreshToken{ExpiresAt: now.Add(time.Hour), LastUsedAt: timePtr(now.Add(-(RefreshReplayRaceGracePeriod + time.Second)))}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRevokeAllOnRefreshMismatch(tt.session, now); got != tt.want {
				t.Fatalf("shouldRevokeAllOnRefreshMismatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldRevokeAllOnLogoutAllFailure(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		session *entities.RefreshToken
		matched bool
		want    bool
	}{
		{name: "mismatch with stale live session", session: &entities.RefreshToken{ExpiresAt: now.Add(time.Hour), LastUsedAt: timePtr(now.Add(-(RefreshReplayRaceGracePeriod + time.Second)))}, matched: false, want: true},
		{name: "mismatch within rotation grace period", session: &entities.RefreshToken{ExpiresAt: now.Add(time.Hour), LastUsedAt: timePtr(now.Add(-(RefreshReplayRaceGracePeriod - time.Second)))}, matched: false, want: false},
		{name: "matched live session with invalid state", session: &entities.RefreshToken{ExpiresAt: now.Add(time.Hour)}, matched: true, want: true},
		{name: "matched revoked session", session: &entities.RefreshToken{IsRevoked: true, ExpiresAt: now.Add(time.Hour)}, matched: true, want: false},
		{name: "matched expired session", session: &entities.RefreshToken{ExpiresAt: now.Add(-time.Second)}, matched: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRevokeAllOnLogoutAllFailure(tt.session, tt.matched, now); got != tt.want {
				t.Fatalf("shouldRevokeAllOnLogoutAllFailure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsTrustedServiceRequest(t *testing.T) {
	tests := []struct {
		name       string
		trustedEnv string
		request    *http.Request
		want       bool
	}{
		{
			name:       "rejects spoofed service user agent from untrusted remote",
			trustedEnv: "198.51.100.10/32",
			request: &http.Request{
				RemoteAddr: "203.0.113.20:1234",
				Header:     http.Header{"User-Agent": []string{"cloudflare-access"}},
			},
			want: false,
		},
		{
			name:       "accepts service user agent from trusted remote",
			trustedEnv: "198.51.100.10/32",
			request: &http.Request{
				RemoteAddr: "198.51.100.10:1234",
				Header:     http.Header{"User-Agent": []string{"cloudflare-access"}},
			},
			want: true,
		},
		{
			name:       "rejects trusted remote without service user agent",
			trustedEnv: "198.51.100.10/32",
			request: &http.Request{
				RemoteAddr: "198.51.100.10:1234",
				Header:     http.Header{"User-Agent": []string{"Go-http-client/1.1"}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TRUSTED_PROXIES", tt.trustedEnv)
			if got := isTrustedServiceRequest(tt.request); got != tt.want {
				t.Fatalf("isTrustedServiceRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func timePtr(value time.Time) *time.Time {
	return &value
}
