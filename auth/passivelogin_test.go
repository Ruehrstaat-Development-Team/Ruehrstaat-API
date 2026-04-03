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

func TestRequestPassiveLoginTokenRateLimitsByClientIP(t *testing.T) {
	cleanup := setupPassiveLoginTestRedis(t)
	defer cleanup()

	ctx := context.Background()
	clientIP := "192.0.2.20"

	for i := 0; i < PassiveLoginRequestMaxAttempts; i++ {
		if _, _, err := RequestPassiveLoginToken(ctx, clientIP); err != nil {
			t.Fatalf("request %d error = %v, want nil", i+1, err)
		}
	}

	if _, _, err := RequestPassiveLoginToken(ctx, clientIP); err != ErrPassiveLoginRequestRateLimited {
		t.Fatalf("blocked request error = %v, want %v", err, ErrPassiveLoginRequestRateLimited)
	}
}

func TestVerifyPassiveLoginTokenRateLimitsFailedAttempts(t *testing.T) {
	cleanup := setupPassiveLoginTestRedis(t)
	defer cleanup()

	ctx := context.Background()
	user := &entities.User{ID: uuid.New()}

	for i := 0; i < PassiveLoginMaxAttempts; i++ {
		if err := VerifyPassiveLoginToken(ctx, "missing-token", user); err != ErrInvalidToken {
			t.Fatalf("attempt %d error = %v, want %v", i+1, err, ErrInvalidToken)
		}
	}

	if err := VerifyPassiveLoginToken(ctx, "missing-token", user); err != ErrPassiveLoginRateLimited {
		t.Fatalf("blocked attempt error = %v, want %v", err, ErrPassiveLoginRateLimited)
	}
}

func TestVerifyPassiveLoginTokenSuccessResetsFailedAttempts(t *testing.T) {
	cleanup := setupPassiveLoginTestRedis(t)
	defer cleanup()

	ctx := context.Background()
	user := &entities.User{ID: uuid.New()}

	for i := 0; i < PassiveLoginMaxAttempts-1; i++ {
		if err := VerifyPassiveLoginToken(ctx, "missing-token", user); err != ErrInvalidToken {
			t.Fatalf("warmup attempt %d error = %v, want %v", i+1, err, ErrInvalidToken)
		}
	}

	cache.BeginSpecificState("passive_login", "valid-token", "pending", PassiveLoginBlockDuration)
	if err := VerifyPassiveLoginToken(ctx, "valid-token", user); err != nil {
		t.Fatalf("VerifyPassiveLoginToken() success error = %v, want nil", err)
	}

	if err := VerifyPassiveLoginToken(ctx, "missing-token", user); err != ErrInvalidToken {
		t.Fatalf("post-success invalid attempt error = %v, want %v", err, ErrInvalidToken)
	}
}

func setupPassiveLoginTestRedis(t *testing.T) func() {
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
