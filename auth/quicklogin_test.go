package auth

import (
	"context"
	"testing"

	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db/entities"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestVerifyQuickLoginTokenRateLimitsFailedAttempts(t *testing.T) {
	cleanup := setupQuickLoginTestRedis(t)
	defer cleanup()

	user := &entities.User{ID: uuid.New()}
	ctx := context.Background()

	for i := 0; i < QuickLoginMaxAttempts; i++ {
		if err := VerifyQuickLoginToken(ctx, "000000", user); err != ErrInvalidToken {
			t.Fatalf("attempt %d error = %v, want %v", i+1, err, ErrInvalidToken)
		}
	}

	if err := VerifyQuickLoginToken(ctx, "000000", user); err != ErrQuickloginRateLimited {
		t.Fatalf("blocked attempt error = %v, want %v", err, ErrQuickloginRateLimited)
	}
}

func TestRequestQuickLoginTokenRateLimitsByClientIP(t *testing.T) {
	cleanup := setupQuickLoginTestRedis(t)
	defer cleanup()

	ctx := context.Background()
	clientIP := "192.0.2.10"

	for i := 0; i < QuickLoginRequestMaxAttempts; i++ {
		if _, _, err := RequestQuickLoginToken(ctx, clientIP); err != nil {
			t.Fatalf("request %d error = %v, want nil", i+1, err)
		}
	}

	if _, _, err := RequestQuickLoginToken(ctx, clientIP); err != ErrQuickloginRequestRateLimited {
		t.Fatalf("blocked request error = %v, want %v", err, ErrQuickloginRequestRateLimited)
	}
}

func TestVerifyQuickLoginTokenSuccessResetsFailedAttempts(t *testing.T) {
	cleanup := setupQuickLoginTestRedis(t)
	defer cleanup()

	user := &entities.User{ID: uuid.New()}
	ctx := context.Background()

	for i := 0; i < QuickLoginMaxAttempts-1; i++ {
		if err := VerifyQuickLoginToken(ctx, "111111", user); err != ErrInvalidToken {
			t.Fatalf("warmup attempt %d error = %v, want %v", i+1, err, ErrInvalidToken)
		}
	}

	cache.BeginSpecificState("quick_login", "123456", "pending", QuickLoginBlockDuration)
	if err := VerifyQuickLoginToken(ctx, "123456", user); err != nil {
		t.Fatalf("VerifyQuickLoginToken() success error = %v, want nil", err)
	}

	if err := VerifyQuickLoginToken(ctx, "111111", user); err != ErrInvalidToken {
		t.Fatalf("post-success invalid attempt error = %v, want %v", err, ErrInvalidToken)
	}
}

func TestCompleteQuickLoginWrongSessionDoesNotConsumeVerifiedState(t *testing.T) {
	cleanup := setupQuickLoginTestRedis(t)
	defer cleanup()

	userID := uuid.New().String()
	cache.BeginSpecificState("quick_login", "123456", "pending", QuickLoginBlockDuration)
	cache.BeginSpecificState("quick_login_verified", "123456", userID, QuickLoginBlockDuration)
	cache.BeginSpecificState("quick_login_session", "123456", "expected-session", QuickLoginBlockDuration)

	if _, err := CompleteQuickLogin("123456", "wrong-session"); err != ErrInvalidToken {
		t.Fatalf("CompleteQuickLogin() wrong session error = %v, want %v", err, ErrInvalidToken)
	}

	if !cache.HasState("quick_login_verified", "123456") {
		t.Fatal("verified state was consumed by wrong session")
	}
	if !cache.HasState("quick_login_session", "123456") {
		t.Fatal("session state was consumed by wrong session")
	}

	gotUserID, err := CompleteQuickLogin("123456", "expected-session")
	if err != nil {
		t.Fatalf("CompleteQuickLogin() retry error = %v, want nil", err)
	}
	if gotUserID != userID {
		t.Fatalf("CompleteQuickLogin() userID = %q, want %q", gotUserID, userID)
	}
}

func TestVerifyQuickLoginTokenSuccessKeepsCompletionPathIntact(t *testing.T) {
	cleanup := setupQuickLoginTestRedis(t)
	defer cleanup()

	user := &entities.User{ID: uuid.New()}
	ctx := context.Background()
	token := "123456"
	sessionID := "expected-session"

	cache.BeginSpecificState("quick_login", token, "pending", QuickLoginBlockDuration)
	cache.BeginSpecificState("quick_login_session", token, sessionID, QuickLoginBlockDuration)

	if err := VerifyQuickLoginToken(ctx, token, user); err != nil {
		t.Fatalf("VerifyQuickLoginToken() error = %v, want nil", err)
	}

	gotUserID, err := CompleteQuickLogin(token, sessionID)
	if err != nil {
		t.Fatalf("CompleteQuickLogin() error = %v, want nil", err)
	}
	if gotUserID != user.ID.String() {
		t.Fatalf("CompleteQuickLogin() userID = %q, want %q", gotUserID, user.ID.String())
	}
}

func TestVerifyQuickLoginTokenBindsFirstVerifier(t *testing.T) {
	cleanup := setupQuickLoginTestRedis(t)
	defer cleanup()

	ctx := context.Background()
	token := "123456"
	sessionID := "expected-session"
	firstUser := &entities.User{ID: uuid.New()}
	secondUser := &entities.User{ID: uuid.New()}

	cache.BeginSpecificState("quick_login", token, "pending", QuickLoginBlockDuration)
	cache.BeginSpecificState("quick_login_session", token, sessionID, QuickLoginBlockDuration)

	if err := VerifyQuickLoginToken(ctx, token, firstUser); err != nil {
		t.Fatalf("first VerifyQuickLoginToken() error = %v, want nil", err)
	}
	if err := VerifyQuickLoginToken(ctx, token, secondUser); err != ErrInvalidToken {
		t.Fatalf("second VerifyQuickLoginToken() error = %v, want %v", err, ErrInvalidToken)
	}

	gotUserID, err := CompleteQuickLogin(token, sessionID)
	if err != nil {
		t.Fatalf("CompleteQuickLogin() error = %v, want nil", err)
	}
	if gotUserID != firstUser.ID.String() {
		t.Fatalf("CompleteQuickLogin() userID = %q, want %q", gotUserID, firstUser.ID.String())
	}
}

func setupQuickLoginTestRedis(t *testing.T) func() {
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
