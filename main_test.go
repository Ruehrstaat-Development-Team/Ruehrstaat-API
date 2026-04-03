package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	rstauth "ruehrstaat-backend/auth"

	"github.com/gin-gonic/gin"
)

func TestShouldCaptureSentryEvent(t *testing.T) {
	tests := []struct {
		statusCode int
		want       bool
	}{
		{statusCode: http.StatusBadRequest, want: false},
		{statusCode: http.StatusUnauthorized, want: false},
		{statusCode: http.StatusTooManyRequests, want: false},
		{statusCode: http.StatusInternalServerError, want: true},
		{statusCode: http.StatusBadGateway, want: true},
	}

	for _, tt := range tests {
		if got := shouldCaptureSentryEvent(tt.statusCode); got != tt.want {
			t.Fatalf("status %d: expected %t, got %t", tt.statusCode, tt.want, got)
		}
	}
}

func TestCorsWildcardDisablesCredentials(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "*")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	c.Request.Header.Set("Origin", "https://evil.example")

	cors()(c)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("expected wildcard allow-origin, got %q", got)
	}

	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "false" {
		t.Fatalf("expected credentials to be disabled for wildcard origin, got %q", got)
	}
}

func TestCorsExplicitOriginKeepsCredentials(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	c.Request.Header.Set("Origin", "https://app.example")

	cors()(c)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Fatalf("expected configured allow-origin, got %q", got)
	}

	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("expected credentials to remain enabled for explicit origin, got %q", got)
	}
}

func TestCorsMultipleOriginsEchoesMatchedOrigin(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example, https://admin.example/path")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	c.Request.Header.Set("Origin", "https://admin.example")

	cors()(c)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://admin.example" {
		t.Fatalf("expected matched request origin, got %q", got)
	}

	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("expected vary origin header, got %q", got)
	}

	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("expected credentials to remain enabled for matched explicit origin, got %q", got)
	}
}

func TestCorsRejectsDisallowedOrigin(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example, https://admin.example")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	c.Request.Header.Set("Origin", "https://evil.example")

	cors()(c)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no allow-origin for disallowed origin, got %q", got)
	}

	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("expected no credentials header for disallowed origin, got %q", got)
	}
}

func TestCorsAllowsCustomTokenHeaders(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodOptions, "/v1/health", nil)
	c.Request.Header.Set("Origin", "https://app.example")

	cors()(c)

	allowedHeaders := w.Header().Get("Access-Control-Allow-Headers")
	for _, header := range []string{"X-RST-User-Id", "X-RST-Token", "X-RST-Client-Id", "X-RST-Client-Secret"} {
		if !strings.Contains(allowedHeaders, header) {
			t.Fatalf("expected %q in allow-headers, got %q", header, allowedHeaders)
		}
	}

	if w.Code != http.StatusOK {
		t.Fatalf("expected preflight to return 200, got %d", w.Code)
	}
}

func TestSanitizeRequestForSentryRedactsSensitiveAuthData(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh?token=secret&code=1234", strings.NewReader(`{"refreshToken":"secret"}`))
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "refresh_token=secret-cookie")
	req.Header.Set("X-API-Key", "secret-key")
	req.Header.Set("X-RST-Token", "secret-rst-token")
	req.Header.Set("X-RST-Client-Id", "secret-client-id")
	req.Header.Set("X-RST-Client-Secret", "secret-client-secret")
	req.Header.Set("X-RST-User-Id", "secret-user-id")
	req.Header.Set("Content-Type", "application/json")

	sanitized := sanitizeRequestForSentry(req)

	if got := sanitized.Header.Get("Authorization"); got != "" {
		t.Fatalf("expected authorization header to be redacted, got %q", got)
	}

	if got := sanitized.Header.Get("Cookie"); got != "" {
		t.Fatalf("expected cookie header to be redacted, got %q", got)
	}

	if got := sanitized.Header.Get("X-API-Key"); got != "" {
		t.Fatalf("expected api key header to be redacted, got %q", got)
	}

	for _, header := range []string{"X-RST-Token", "X-RST-Client-Id", "X-RST-Client-Secret", "X-RST-User-Id"} {
		if got := sanitized.Header.Get(header); got != "" {
			t.Fatalf("expected %s header to be redacted, got %q", header, got)
		}
	}

	if got := sanitized.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected non-sensitive headers to be preserved, got %q", got)
	}

	if sanitized.URL.RawQuery != "" {
		t.Fatalf("expected query string to be removed, got %q", sanitized.URL.RawQuery)
	}

	if sanitized.RequestURI != "/v1/auth/refresh" {
		t.Fatalf("expected request uri to be reduced to path, got %q", sanitized.RequestURI)
	}

	body, err := io.ReadAll(sanitized.Body)
	if err != nil {
		t.Fatalf("expected sanitized body to be readable: %v", err)
	}

	if len(body) != 0 {
		t.Fatalf("expected request body to be removed, got %q", string(body))
	}
}

func TestTrustedProxiesFromEnv(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "127.0.0.1/32, 10.0.0.0/8 , ::1/128")

	trusted, err := rstauth.TrustedProxiesFromEnv()
	if err != nil {
		t.Fatalf("TrustedProxiesFromEnv() error = %v, want nil", err)
	}

	want := []string{"127.0.0.1/32", "10.0.0.0/8", "::1/128"}
	if len(trusted) != len(want) {
		t.Fatalf("TrustedProxiesFromEnv() len = %d, want %d", len(trusted), len(want))
	}
	for i := range want {
		if trusted[i] != want[i] {
			t.Fatalf("TrustedProxiesFromEnv()[%d] = %q, want %q", i, trusted[i], want[i])
		}
	}
}
