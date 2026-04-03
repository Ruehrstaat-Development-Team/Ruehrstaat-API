package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/util"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRequireFreshBrowserSessionRejectsCrossSiteCookieRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "none")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "https://api.example/v1/users/link/fido2/begin", nil)

	_, _, err := RequireFreshBrowserSession(ctx)
	if err != ErrForbidden {
		t.Fatalf("RequireFreshBrowserSession() error = %v, want %v", err, ErrForbidden)
	}
}

func TestRequireSessionBoundAuthRejectsCrossSiteCookieRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "none")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "https://api.example/v1/users/@me", nil)

	_, gotErr := RequireSessionBoundAuth(ctx)
	if gotErr != ErrForbidden {
		t.Fatalf("RequireSessionBoundAuth() error = %v, want %v", gotErr, ErrForbidden)
	}
}

func TestRequireSessionBoundAuthPreservesBrowserRejectionWithBearerHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "none")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "https://api.example/v1/users/@me", nil)
	ctx.Request.Header.Set("Authorization", "Bearer invalid")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0")
	ctx.Request.Header.Set("Accept", "application/json")

	_, gotErr := RequireSessionBoundAuth(ctx)
	if gotErr != ErrForbidden {
		t.Fatalf("RequireSessionBoundAuth() error = %v, want %v", gotErr, ErrForbidden)
	}
}

func TestRequireSessionBoundAuthAllowsNonBrowserBearerFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "none")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")
	t.Setenv("JWT_IDENTITY_SECRET", "12345678901234567890123456789012")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "https://api.example/v1/users/@me", nil)
	ctx.Request.Header.Set("Authorization", "Bearer invalid")
	ctx.Request.Header.Set("User-Agent", "Go-http-client/1.1")
	ctx.Request.Header.Set("Accept", "application/json")

	_, gotErr := RequireSessionBoundAuth(ctx)
	if gotErr != ErrUnauthorized {
		t.Fatalf("RequireSessionBoundAuth() error = %v, want %v", gotErr, ErrUnauthorized)
	}
}

func TestRequireSessionBoundAuthAllowsActiveServiceSessionBearerToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("REFRESH_COOKIE_SAMESITE", "none")
	t.Setenv("FRONTEND_URL", "https://app.example")
	t.Setenv("BACKEND_URL", "https://api.example")
	t.Setenv("JWT_IDENTITY_SECRET", strings.Repeat("i", 32))

	cleanupDB := setupSessionBindingTestDB(t)
	defer cleanupDB()

	userID := uuid.New()
	sessionID := uuid.New()
	accessExpiresAt := time.Now().Add(time.Hour)
	identityToken, jti, err := generateIdentityTokenWithSession(getIdentityTokenSecret(), userID.String(), sessionID, accessExpiresAt.Unix())
	if err != nil {
		t.Fatalf("generateIdentityTokenWithSession() error = %v", err)
	}

	if err := db.DB.WithContext(context.Background()).Exec(
		"INSERT INTO users (id, is_activated, is_banned) VALUES (?, ?, ?)",
		userID.String(), true, false,
	).Error; err != nil {
		t.Fatalf("insert user error = %v", err)
	}

	if err := db.DB.WithContext(context.Background()).Exec(
		"INSERT INTO refresh_tokens (id, user_id, is_revoked, expires_at, session_type) VALUES (?, ?, ?, ?, ?)",
		sessionID.String(), userID.String(), false, accessExpiresAt.Add(time.Hour), entities.SessionTypeService,
	).Error; err != nil {
		t.Fatalf("insert refresh token error = %v", err)
	}

	if err := db.DB.WithContext(context.Background()).Create(&entities.AccessTokenJTI{
		ID:        uuid.New(),
		UserID:    userID,
		SessionID: sessionID,
		JTIHash:   util.HashToken(jti),
		ExpiresAt: accessExpiresAt,
	}).Error; err != nil {
		t.Fatalf("insert access token jti error = %v", err)
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "https://api.example/v1/users/@me", nil)
	ctx.Request.Header.Set("Authorization", "Bearer "+identityToken)
	ctx.Request.Header.Set("User-Agent", "Go-http-client/1.1")
	ctx.Request.Header.Set("Accept", "application/json")

	user, gotErr := RequireSessionBoundAuth(ctx)
	if gotErr != nil {
		t.Fatalf("RequireSessionBoundAuth() error = %v, want nil", gotErr)
	}
	if user == nil {
		t.Fatal("RequireSessionBoundAuth() user = nil, want user")
	}
	if user.ID != userID {
		t.Fatalf("RequireSessionBoundAuth() user.ID = %v, want %v", user.ID, userID)
	}
}

func TestIsActiveServiceSession(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		session *entities.RefreshToken
		want    bool
	}{
		{name: "missing session", session: nil, want: false},
		{name: "browser session", session: &entities.RefreshToken{ExpiresAt: now.Add(time.Hour), SessionType: entities.SessionTypeBrowser}, want: false},
		{name: "revoked service session", session: &entities.RefreshToken{IsRevoked: true, ExpiresAt: now.Add(time.Hour), SessionType: entities.SessionTypeService}, want: false},
		{name: "expired service session", session: &entities.RefreshToken{ExpiresAt: now.Add(-time.Second), SessionType: entities.SessionTypeService}, want: false},
		{name: "active service session", session: &entities.RefreshToken{ExpiresAt: now.Add(time.Hour), SessionType: entities.SessionTypeService}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isActiveServiceSession(tt.session, now); got != tt.want {
				t.Fatalf("isActiveServiceSession() = %v, want %v", got, tt.want)
			}
		})
	}
}

func setupSessionBindingTestDB(t *testing.T) func() {
	t.Helper()

	database, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	previous := db.DB
	db.DB = database

	statements := []string{
		"CREATE TABLE users (id TEXT PRIMARY KEY, is_activated BOOLEAN NOT NULL, is_banned BOOLEAN NOT NULL, deleted_at DATETIME)",
		"CREATE TABLE refresh_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT, is_revoked BOOLEAN NOT NULL, expires_at DATETIME NOT NULL, session_type TEXT NOT NULL)",
		"CREATE TABLE access_token_jtis (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, session_id TEXT NOT NULL, jti_hash TEXT NOT NULL, expires_at DATETIME NOT NULL, created_at DATETIME)",
	}

	for _, statement := range statements {
		if err := database.Exec(statement).Error; err != nil {
			t.Fatalf("failed to create test table with %q: %v", statement, err)
		}
	}

	return func() {
		sqlDB, err := database.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
		db.DB = previous
	}
}
