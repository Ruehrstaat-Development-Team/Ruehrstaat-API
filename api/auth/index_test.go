package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authpkg "ruehrstaat-backend/auth"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/errors"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestAuthCookieHandlersReturnInvalidTokenWhenRefreshCookieMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	tests := []struct {
		name    string
		handler func(*gin.Context)
	}{
		{name: "refresh", handler: refreshToken},
		{name: "logout", handler: logout},
		{name: "logout all", handler: logoutAll},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "https://api.example/v1/auth", nil)
			c.Request.Header.Set("Origin", "https://app.example")

			tt.handler(c)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
			}

			var body struct {
				Code string `json:"code"`
				Name string `json:"name"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("failed to decode body: %v", err)
			}
			if body.Code != "A1001" {
				t.Fatalf("code = %q, want %q", body.Code, "A1001")
			}
			if body.Name != "A1001" {
				t.Fatalf("name = %q, want %q", body.Name, "A1001")
			}

			cookie := w.Header().Get("Set-Cookie")
			if tt.name == "refresh" {
				if cookie != "" {
					t.Fatalf("Set-Cookie = %q, want empty", cookie)
				}
				return
			}

			if !strings.Contains(cookie, "refresh_token=") || !strings.Contains(cookie, "Max-Age=0") {
				t.Fatalf("Set-Cookie = %q, want cleared refresh cookie", cookie)
			}
		})
	}
}

func TestLogoutHandlersClearRefreshCookieOnInvalidRefreshToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := strings.Repeat("r", 16)
	t.Setenv("JWT_REFRESH_SECRET", secret)
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	invalidAudienceToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "Ruehrstaat Auth",
		"aud": "wrong-audience",
		"sub": uuid.New().String(),
		"sid": uuid.New().String(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"jti": uuid.New().String(),
	})
	refreshToken, err := invalidAudienceToken.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString() returned error: %v", err)
	}

	tests := []struct {
		name    string
		handler func(*gin.Context)
	}{
		{name: "logout", handler: logout},
		{name: "logout all", handler: logoutAll},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "https://api.example/v1/auth", nil)
			c.Request.Header.Set("Origin", "https://app.example")
			c.Request.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})

			tt.handler(c)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
			}

			cookie := w.Header().Get("Set-Cookie")
			if !strings.Contains(cookie, "refresh_token=") || !strings.Contains(cookie, "Max-Age=0") {
				t.Fatalf("Set-Cookie = %q, want cleared refresh cookie", cookie)
			}
		})
	}
}

func TestAuthCookieHandlersRejectCrossSiteRequestsWhenRefreshCookieIsCrossSite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "none")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	tests := []struct {
		name    string
		handler func(*gin.Context)
	}{
		{name: "refresh", handler: refreshToken},
		{name: "logout", handler: logout},
		{name: "logout all", handler: logoutAll},
		{name: "quicklogin completion", handler: completeQuickLogin},
		{name: "passivelogin completion", handler: completePassiveLogin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "https://api.example/v1/auth", nil)
			if tt.name == "quicklogin completion" || tt.name == "passivelogin completion" {
				c.Request.Header.Set("Sec-Fetch-Site", "cross-site")
			}

			tt.handler(c)

			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
			}

			var body struct {
				Code string `json:"code"`
				Name string `json:"name"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("failed to decode body: %v", err)
			}
			if body.Code != "A4000" {
				t.Fatalf("code = %q, want %q", body.Code, "A4000")
			}
			if body.Name != "A4000" {
				t.Fatalf("name = %q, want %q", body.Name, "A4000")
			}
		})
	}
}

func TestAuthCookieHandlersAllowConfiguredOriginBeforeCookieValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	tests := []struct {
		name    string
		handler func(*gin.Context)
	}{
		{name: "refresh", handler: refreshToken},
		{name: "logout", handler: logout},
		{name: "logout all", handler: logoutAll},
	}

	for _, sameSite := range []string{"lax", "strict", "none"} {
		t.Run(sameSite, func(t *testing.T) {
			t.Setenv("REFRESH_COOKIE_SAMESITE", sameSite)

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					w := httptest.NewRecorder()
					c, _ := gin.CreateTestContext(w)
					c.Request = httptest.NewRequest(http.MethodPost, "https://api.example/v1/auth", nil)
					c.Request.Header.Set("Origin", "https://app.example")

					tt.handler(c)

					if w.Code != http.StatusUnauthorized {
						t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
					}

					var body struct {
						Code string `json:"code"`
						Name string `json:"name"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
						t.Fatalf("failed to decode body: %v", err)
					}
					if body.Code != "A1001" {
						t.Fatalf("code = %q, want %q", body.Code, "A1001")
					}
					if body.Name != "A1001" {
						t.Fatalf("name = %q, want %q", body.Name, "A1001")
					}
				})
			}
		})
	}
}

func TestAuthCookieHandlersRejectRequestsWithoutTrustedOriginRegardlessOfSameSite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	tests := []struct {
		name    string
		handler func(*gin.Context)
	}{
		{name: "refresh", handler: refreshToken},
		{name: "logout", handler: logout},
		{name: "logout all", handler: logoutAll},
	}

	for _, sameSite := range []string{"lax", "strict", "none"} {
		t.Run(sameSite, func(t *testing.T) {
			t.Setenv("REFRESH_COOKIE_SAMESITE", sameSite)

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					w := httptest.NewRecorder()
					c, _ := gin.CreateTestContext(w)
					c.Request = httptest.NewRequest(http.MethodPost, "https://api.example/v1/auth", nil)

					tt.handler(c)

					if w.Code != http.StatusForbidden {
						t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
					}

					var body struct {
						Code string `json:"code"`
						Name string `json:"name"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
						t.Fatalf("failed to decode body: %v", err)
					}
					if body.Code != "A4000" {
						t.Fatalf("code = %q, want %q", body.Code, "A4000")
					}
					if body.Name != "A4000" {
						t.Fatalf("name = %q, want %q", body.Name, "A4000")
					}
				})
			}
		})
	}
}

func TestAuthCookieIssuingHandlersAllowConfiguredOriginBeforeDTOValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "none")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	tests := []struct {
		name    string
		handler func(*gin.Context)
	}{
		{name: "login", handler: login},
		{name: "login totp", handler: loginTotp},
		{name: "fido2 end", handler: endLoginFido2},
		{name: "quicklogin completion", handler: completeQuickLogin},
		{name: "passivelogin completion", handler: completePassiveLogin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "https://api.example/v1/auth", nil)
			c.Request.Header.Set("Origin", "https://app.example")

			tt.handler(c)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestAuthCookieIssuingHandlersRejectBrowserRequestsWithoutTrustedOriginMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "none")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	tests := []struct {
		name    string
		handler func(*gin.Context)
		body    string
	}{
		{name: "login", handler: login, body: `{"email":"user@example.com","password":"secret"}`},
		{name: "login totp", handler: loginTotp, body: `{"state":"state-123","code":"123456"}`},
		{name: "fido2 end", handler: endLoginFido2, body: `{}`},
		{name: "quicklogin completion", handler: completeQuickLogin, body: `{"token":"123456","sessionId":"abc"}`},
		{name: "passivelogin completion", handler: completePassiveLogin, body: `{"token":"123456","sessionId":"abc"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "https://api.example/v1/auth", strings.NewReader(tt.body))
			c.Request.Header.Set("Content-Type", "application/json")
			c.Request.Header.Set("User-Agent", "Mozilla/5.0")
			c.Request.Header.Set("Accept", "application/json")

			tt.handler(c)

			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d, body = %s", w.Code, http.StatusForbidden, w.Body.String())
			}
		})
	}
}

func TestAuthCookieIssuingHandlersAllowNonBrowserRequestsWithoutOriginMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "none")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	tests := []struct {
		name    string
		handler func(*gin.Context)
	}{
		{name: "login", handler: login},
		{name: "login totp", handler: loginTotp},
		{name: "fido2 end", handler: endLoginFido2},
		{name: "quicklogin completion", handler: completeQuickLogin},
		{name: "passivelogin completion", handler: completePassiveLogin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "https://api.example/v1/auth", nil)
			c.Request.Header.Set("User-Agent", "Go-http-client/1.1")
			c.Request.Header.Set("Accept", "application/json")

			tt.handler(c)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d, body = %s", w.Code, http.StatusBadRequest, w.Body.String())
			}
		})
	}
}

func TestAuthCookieIssuingHandlersRejectCrossSiteRequestsUnderLaxCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "lax")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	tests := []struct {
		name    string
		handler func(*gin.Context)
	}{
		{name: "login", handler: login},
		{name: "login totp", handler: loginTotp},
		{name: "fido2 end", handler: endLoginFido2},
		{name: "quicklogin completion", handler: completeQuickLogin},
		{name: "passivelogin completion", handler: completePassiveLogin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "https://api.example/v1/auth", nil)
			c.Request.Header.Set("Sec-Fetch-Site", "cross-site")

			tt.handler(c)

			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
			}
		})
	}
}

func TestSetRefreshTokenCookieUsesConfiguredSameSite(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name    string
		env     string
		request *http.Request
		want    string
	}{
		{name: "default lax", env: "", request: httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil), want: "SameSite=Lax"},
		{name: "strict", env: "strict", request: httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil), want: "SameSite=Strict"},
		{name: "none on secure request", env: "none", request: httptest.NewRequest(http.MethodPost, "https://api.example/v1/auth/login", nil), want: "SameSite=None"},
		{name: "none falls back to lax on insecure request", env: "none", request: httptest.NewRequest(http.MethodPost, "http://api.example/v1/auth/login", nil), want: "SameSite=Lax"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("REFRESH_COOKIE_SAMESITE", tt.env)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = tt.request

			setRefreshTokenCookie(c, "secret", 60)

			cookie := w.Header().Get("Set-Cookie")
			if !strings.Contains(cookie, tt.want) {
				t.Fatalf("Set-Cookie = %q, want substring %q", cookie, tt.want)
			}
		})
	}
}

func TestWriteSessionTokenResponseUsesStandardContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)

	writeSessionTokenResponse(c, &authpkg.TokenPair{
		RefreshToken: "refresh-secret",
		IdenityToken: "identity-token",
		ExpiresAt:    1234567890,
		SessionID:    uuid.New(),
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["token"] != "identity-token" {
		t.Fatalf("token = %v, want %q", body["token"], "identity-token")
	}
	if body["expiresAt"] != float64(1234567890) {
		t.Fatalf("expiresAt = %v, want %v", body["expiresAt"], float64(1234567890))
	}
	if _, exists := body["sessionId"]; exists {
		t.Fatal("sessionId should not be exposed in response body")
	}
	if _, exists := body["refreshToken"]; exists {
		t.Fatal("refreshToken should not be exposed in response body")
	}
	if cookie := w.Header().Get("Set-Cookie"); !strings.Contains(cookie, "refresh_token=refresh-secret") {
		t.Fatalf("Set-Cookie = %q, want refresh token cookie", cookie)
	}
}

func TestNextLoginOtpState(t *testing.T) {
	cleanup := setupAuthHandlerTestRedis(t)
	defer cleanup()

	currentState := beginLoginOtpState("user-123", "hash-1")

	var payload map[string]string
	if ok := cache.GetState("login_otp", currentState, &payload); !ok {
		t.Fatal("initial otp state missing")
	}
	if payload["user_id"] != "user-123" {
		t.Fatalf("user_id = %q, want %q", payload["user_id"], "user-123")
	}
	if payload["password_hash"] != "hash-1" {
		t.Fatalf("password_hash = %q, want %q", payload["password_hash"], "hash-1")
	}

	t.Run("preserves current state on otp rate limit", func(t *testing.T) {
		nextState := nextLoginOtpState(currentState, "user-123", "hash-1", authpkg.ErrUserOtpRateLimited)
		if nextState != currentState {
			t.Fatalf("nextLoginOtpState() = %q, want %q", nextState, currentState)
		}
		if !cache.HasState("login_otp", currentState) {
			t.Fatal("current otp state was removed on rate limit")
		}
	})

	t.Run("rotates state on wrong otp", func(t *testing.T) {
		nextState := nextLoginOtpState(currentState, "user-123", "hash-2", authpkg.ErrUserOtpWrong)
		if nextState == "" || nextState == currentState {
			t.Fatalf("nextLoginOtpState() = %q, want new state", nextState)
		}
		if cache.HasState("login_otp", currentState) {
			t.Fatal("old otp state still exists after wrong otp")
		}
		if !cache.HasState("login_otp", nextState) {
			t.Fatal("new otp state missing after wrong otp")
		}
		var nextPayload map[string]string
		if ok := cache.GetState("login_otp", nextState, &nextPayload); !ok {
			t.Fatal("new otp state payload missing after wrong otp")
		}
		if nextPayload["password_hash"] != "hash-2" {
			t.Fatalf("rotated password_hash = %q, want %q", nextPayload["password_hash"], "hash-2")
		}
		currentState = nextState
	})

	t.Run("consumes state on terminal result", func(t *testing.T) {
		nextState := nextLoginOtpState(currentState, "user-123", "hash-2", nil)
		if nextState != "" {
			t.Fatalf("nextLoginOtpState() = %q, want empty", nextState)
		}
		if cache.HasState("login_otp", currentState) {
			t.Fatal("otp state still exists after terminal result")
		}
	})
}

func TestIsLoginTotpClientOtpError(t *testing.T) {
	tests := []struct {
		name string
		err  *errors.RstError
		want bool
	}{
		{name: "missing otp", err: authpkg.ErrUserOtpMissing, want: true},
		{name: "wrong otp", err: authpkg.ErrUserOtpWrong, want: true},
		{name: "rate limited", err: authpkg.ErrUserOtpRateLimited, want: false},
		{name: "invalid state", err: authpkg.ErrInvalidState, want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLoginTotpClientOtpError(tt.err); got != tt.want {
				t.Fatalf("isLoginTotpClientOtpError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiscordLoginCallbackRedirectsBrowserFailuresToFrontend(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FRONTEND_URL", "https://frontend.ruehrstaat.org/app")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/auth/discord/callback", nil)
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml")

	discordLoginCallback(c)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}
	location := w.Header().Get("Location")
	if location != "https://frontend.ruehrstaat.org/app/auth/callbacks/discord?success=false" {
		t.Fatalf("Location = %q, want %q", location, "https://frontend.ruehrstaat.org/app/auth/callbacks/discord?success=false")
	}
}

func TestDiscordLoginCallbackFallsBackToCallbackPageOnInvalidStoredRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FRONTEND_URL", "https://frontend.ruehrstaat.org/app")

	cleanup := setupAuthHandlerTestRedis(t)
	defer cleanup()

	cache.BeginSpecificState("user_discord_login", "state-123", map[string]string{
		"redirect_to":     "https://evil.example/callback",
		"code_verifier":   "verifier",
		"browser_binding": "expected-binding",
	}, 0)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/auth/discord/callback?state=state-123&code=oauth-code", nil)
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml")
	c.Request.AddCookie(&http.Cookie{Name: discordLoginBindingCookieName, Value: "expected-binding"})

	discordLoginCallback(c)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}
	location := w.Header().Get("Location")
	if location != "https://frontend.ruehrstaat.org/app/auth/callbacks/discord?success=false" {
		t.Fatalf("Location = %q, want %q", location, "https://frontend.ruehrstaat.org/app/auth/callbacks/discord?success=false")
	}
}

func TestDiscordLoginCallbackUsesLocaleAwareFallbackOnMissingState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FRONTEND_URL", "https://frontend.ruehrstaat.org/app")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/auth/discord/callback", nil)
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml")
	c.Request.Header.Set("Referer", "https://frontend.ruehrstaat.org/app/de/login")

	discordLoginCallback(c)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}
	location := w.Header().Get("Location")
	if location != "https://frontend.ruehrstaat.org/app/de/auth/callbacks/discord?success=false" {
		t.Fatalf("Location = %q, want %q", location, "https://frontend.ruehrstaat.org/app/de/auth/callbacks/discord?success=false")
	}
}

func TestDiscordLoginCallbackRejectsMismatchedBrowserBindingWithoutConsumingState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FRONTEND_URL", "https://frontend.ruehrstaat.org/app")

	cleanup := setupAuthHandlerTestRedis(t)
	defer cleanup()

	cache.BeginSpecificState("user_discord_login", "state-123", map[string]string{
		"redirect_to":     "https://frontend.ruehrstaat.org/app/welcome",
		"code_verifier":   "verifier",
		"browser_binding": "expected-binding",
	}, 0)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/auth/discord/callback?state=state-123&code=oauth-code", nil)
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml")
	c.Request.AddCookie(&http.Cookie{Name: discordLoginBindingCookieName, Value: "wrong-binding"})

	discordLoginCallback(c)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}
	location := w.Header().Get("Location")
	if location != "https://frontend.ruehrstaat.org/app/welcome?success=false" {
		t.Fatalf("Location = %q, want %q", location, "https://frontend.ruehrstaat.org/app/welcome?success=false")
	}
	if !cache.HasState("user_discord_login", "state-123") {
		t.Fatal("oauth state was consumed on browser binding mismatch")
	}
}

func TestVerifyLoginHandlersPreserveForbiddenOriginErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "none")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	tests := []struct {
		name    string
		handler gin.HandlerFunc
	}{
		{name: "quicklogin verify", handler: verifyQuickLoginToken},
		{name: "passivelogin verify", handler: verifyPassiveLoginToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPut, "https://api.example/v1/auth", strings.NewReader(`{"token":"123456"}`))
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

func TestCompletePassiveLoginReturnsNotYetVerifiedError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	cleanup := setupAuthHandlerTestRedis(t)
	defer cleanup()

	cache.BeginSpecificState("passive_login", "token-123", "pending", time.Minute)
	cache.BeginSpecificState("passive_login_session", "token-123", "session-123", time.Minute)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "https://api.example/v1/auth/passivelogin", strings.NewReader(`{"token":"token-123","sessionId":"session-123"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("Origin", "https://app.example")

	completePassiveLogin(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	var body struct {
		Code  string `json:"code"`
		Name  string `json:"name"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body.Code != "A5015" || body.Name != "A5015" {
		t.Fatalf("response = %+v, want A5015 not-yet-verified error", body)
	}
}

func setupAuthHandlerTestRedis(t *testing.T) func() {
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
