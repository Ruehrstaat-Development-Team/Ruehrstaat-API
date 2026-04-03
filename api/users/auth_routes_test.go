package users

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db/entities"
	"strings"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestSensitiveUserRoutesRejectLegacyBearerOnlyIdentityTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Setenv("JWT_IDENTITY_SECRET", strings.Repeat("i", 32))
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")
	legacyToken := mustLegacyIdentityToken(t, strings.Repeat("i", 32))

	tests := []struct {
		name        string
		handler     gin.HandlerFunc
		method      string
		target      string
		params      gin.Params
		body        string
		contentType string
	}{
		{name: "get user", handler: getUser, method: http.MethodGet, target: "/users/@me", params: gin.Params{{Key: "id", Value: "@me"}}},
		{name: "admin get users", handler: adminGetUsers, method: http.MethodGet, target: "/users/admin/"},
		{name: "get fido2 links", handler: getFido2Links, method: http.MethodGet, target: "/users/link/fido2/all"},
		{name: "disable totp", handler: disableTotp, method: http.MethodPost, target: "/users/totp/disable", body: `{\"code\":\"123456\"}`, contentType: "application/json"},
		{name: "unlink discord", handler: unlinkDiscord, method: http.MethodDelete, target: "/users/link/discord"},
		{name: "set locale", handler: setLocale, method: http.MethodPatch, target: "/users/locale?locale=en"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			req := httptest.NewRequest(tt.method, "https://api.example"+tt.target, strings.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer "+legacyToken)
			req.Header.Set("Origin", "https://app.example")
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			ctx.Request = req
			ctx.Params = tt.params

			tt.handler(ctx)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d, body = %s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
			}
		})
	}
}

func TestChangeEmailDoesNotRequireExistingBrowserSessionBeforeValidatingRouteInput(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/users/not-a-uuid/change-email", strings.NewReader(`{"emailChangeToken":"token-ref"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "not-a-uuid"}}

	changeEmail(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

func TestActivationAndResetRoutesRequireBodyTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)

	userID := uuid.New().String()
	tests := []struct {
		name    string
		handler gin.HandlerFunc
		method  string
		target  string
		body    string
		params  gin.Params
	}{
		{name: "activate ignores query token", handler: activateUser, method: http.MethodPost, target: "/users/" + userID + "/activate?activation=token-ref", body: `{}`, params: gin.Params{{Key: "id", Value: userID}}},
		{name: "reset ignores query token", handler: resetPassword, method: http.MethodPut, target: "/users/" + userID + "/password-reset?ret=token-ref", body: `{"password":"Password123!"}`, params: gin.Params{{Key: "id", Value: userID}}},
		{name: "change email ignores query token", handler: changeEmail, method: http.MethodPost, target: "/users/" + userID + "/change-email?ect=token-ref", body: `{}`, params: gin.Params{{Key: "id", Value: userID}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body))
			ctx.Request.Header.Set("Content-Type", "application/json")
			ctx.Params = tt.params

			tt.handler(ctx)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d, body = %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
		})
	}
}

func TestRequestPasswordResetRequiresBodyEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name   string
		target string
		body   string
	}{
		{name: "ignores query email", target: "/users/password-reset/request?email=test@example.com", body: `{}`},
		{name: "requires json body", target: "/users/password-reset/request", body: ``},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader(tt.body))
			ctx.Request.Header.Set("Content-Type", "application/json")

			requestPasswordReset(ctx)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d, body = %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
		})
	}
}

func mustLegacyIdentityToken(t *testing.T, secret string) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "Ruehrstaat Auth",
		"aud": "ruehrstaat.org",
		"sub": uuid.New().String(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString() returned error: %v", err)
	}

	return tokenString
}

func TestHasFreshDiscordLinkCallbackSession(t *testing.T) {
	now := time.Now()
	userID := uuid.New()
	sessionID := uuid.New()

	tests := []struct {
		name        string
		liveUserID  uuid.UUID
		liveSession uuid.UUID
		authTime    time.Time
		want        bool
	}{
		{name: "matching fresh session", liveUserID: userID, liveSession: sessionID, authTime: now.Add(-(time.Minute)), want: true},
		{name: "stale session", liveUserID: userID, liveSession: sessionID, authTime: now.Add(-(auth.FreshBrowserSessionMaxAge + time.Second)), want: false},
		{name: "wrong user", liveUserID: uuid.New(), liveSession: sessionID, authTime: now.Add(-(time.Minute)), want: false},
		{name: "wrong session", liveUserID: userID, liveSession: uuid.New(), authTime: now.Add(-(time.Minute)), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			liveUser := &entities.User{ID: tt.liveUserID}
			liveSessionObj := &entities.RefreshToken{ID: tt.liveSession, AuthTime: tt.authTime}

			if got := hasFreshDiscordLinkCallbackSession(liveUser, liveSessionObj, userID, sessionID, now); got != tt.want {
				t.Fatalf("hasFreshDiscordLinkCallbackSession() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiscordLinkCallbackRejectsMismatchedBrowserBindingWithoutConsumingState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FRONTEND_URL", "https://frontend.ruehrstaat.org/app")

	cleanup := setupUsersHandlerTestRedis(t)
	defer cleanup()

	userID := uuid.New()
	sessionID := uuid.New()
	cache.BeginSpecificState("user_discord_link", "state-123", map[string]string{
		"redirect_to":     "https://frontend.ruehrstaat.org/app/settings",
		"user_id":         userID.String(),
		"session_id":      sessionID.String(),
		"code_verifier":   "verifier",
		"browser_binding": "expected-binding",
	}, 0)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/users/link/discord/callback?state=state-123&code=oauth-code", nil)
	c.Request.AddCookie(&http.Cookie{Name: discordLinkBindingCookieName, Value: "wrong-binding"})

	discordLinkCallback(c)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}
	location := w.Header().Get("Location")
	parsedLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(Location) returned error: %v", err)
	}
	if parsedLocation.Scheme != "https" || parsedLocation.Host != "frontend.ruehrstaat.org" || parsedLocation.Path != "/app/settings" {
		t.Fatalf("Location = %q, want redirect to frontend settings", location)
	}
	if parsedLocation.Query().Get("success") != "false" || parsedLocation.Query().Get("rs") != "1" {
		t.Fatalf("Location query = %q, want success=false and rs=1", parsedLocation.RawQuery)
	}
	if !cache.HasState("user_discord_link", "state-123") {
		t.Fatal("oauth state was consumed on browser binding mismatch")
	}
}

func TestSensitiveUserSessionHandlersPreserveForbiddenOriginErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "none")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	tests := []struct {
		name    string
		handler gin.HandlerFunc
		method  string
		target  string
		body    string
	}{
		{name: "change password", handler: changePassword, method: http.MethodPatch, target: "/v1/users/password", body: `{"oldPassword":"old","newPassword":"new"}`},
		{name: "request email change", handler: requestEmailChange, method: http.MethodPost, target: "/v1/users/change-email/request", body: `{"newEmail":"user@example.com","password":"secret"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(tt.method, "https://api.example"+tt.target, strings.NewReader(tt.body))
			c.Request.Header.Set("Content-Type", "application/json")

			tt.handler(c)

			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d, body = %s", w.Code, http.StatusForbidden, w.Body.String())
			}

			var body struct {
				Code string `json:"code"`
				Name string `json:"name"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("failed to decode body: %v", err)
			}
			if body.Code != "A4000" || body.Name != "A4000" {
				t.Fatalf("response = %+v, want forbidden auth error", body)
			}
		})
	}
}

func TestDiscordLinkCallbackRedirectsBrowserFailuresToFrontend(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FRONTEND_URL", "https://frontend.ruehrstaat.org/app")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/users/link/discord/callback", nil)
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml")

	discordLinkCallback(c)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}
	location := w.Header().Get("Location")
	if location != "https://frontend.ruehrstaat.org/app?rs=1&success=false" {
		t.Fatalf("Location = %q, want %q", location, "https://frontend.ruehrstaat.org/app?rs=1&success=false")
	}
}

func TestDiscordLinkCallbackFallsBackToFrontendOnInvalidStoredRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FRONTEND_URL", "https://frontend.ruehrstaat.org/app")

	cleanup := setupUsersHandlerTestRedis(t)
	defer cleanup()

	userID := uuid.New()
	sessionID := uuid.New()
	cache.BeginSpecificState("user_discord_link", "state-123", map[string]string{
		"redirect_to":     "https://evil.example/callback",
		"user_id":         userID.String(),
		"session_id":      sessionID.String(),
		"code_verifier":   "verifier",
		"browser_binding": "expected-binding",
	}, 0)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/users/link/discord/callback?state=state-123&code=oauth-code", nil)
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml")

	discordLinkCallback(c)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}
	location := w.Header().Get("Location")
	if location != "https://frontend.ruehrstaat.org/app?rs=1&success=false" {
		t.Fatalf("Location = %q, want %q", location, "https://frontend.ruehrstaat.org/app?rs=1&success=false")
	}
}

func setupUsersHandlerTestRedis(t *testing.T) func() {
	t.Helper()

	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}

	previous := cache.Redis
	cache.Redis = redis.NewClient(&redis.Options{Addr: server.Addr()})

	return func() {
		_ = cache.Redis.Close()
		cache.Redis = previous
		server.Close()
	}
}
