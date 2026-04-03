package auth

import (
	"strings"
	"testing"

	"ruehrstaat-backend/cache"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestResolveFrontendTokenReferenceDoesNotFallbackToRawToken(t *testing.T) {
	t.Setenv("JWT_IDENTITY_SECRET", strings.Repeat("a", 32))

	if got := ResolveActivationTokenReference("legacy-raw-token"); got != "" {
		t.Fatalf("ResolveActivationTokenReference() = %q, want empty string", got)
	}
}

func TestResolveFrontendTokenReferenceReturnsStoredToken(t *testing.T) {
	t.Setenv("JWT_IDENTITY_SECRET", strings.Repeat("a", 32))

	ref := createFrontendTokenReference(activationLinkRefCategory, "secret-token")
	if got := ResolveActivationTokenReference(ref); got != "secret-token" {
		t.Fatalf("ResolveActivationTokenReference() = %q, want %q", got, "secret-token")
	}
}

func TestResolveFrontendTokenReferenceRejectsWrongCategory(t *testing.T) {
	t.Setenv("JWT_IDENTITY_SECRET", strings.Repeat("a", 32))

	ref := createFrontendTokenReference(passwordResetLinkRefCategory, "secret-token")
	if got := ResolveActivationTokenReference(ref); got != "" {
		t.Fatalf("ResolveActivationTokenReference() = %q, want empty string", got)
	}
}

func TestResolveFrontendTokenReferenceSupportsLegacyOpaqueCacheReference(t *testing.T) {
	t.Setenv("JWT_IDENTITY_SECRET", strings.Repeat("a", 32))
	cleanup := setupAuthTestRedis(t)
	defer cleanup()

	ref := cache.BeginState(passwordResetLinkRefCategory, "secret-token", 0)
	if got := ResolvePasswordResetTokenReference(ref); got != "secret-token" {
		t.Fatalf("ResolvePasswordResetTokenReference() = %q, want %q", got, "secret-token")
	}
}

func setupAuthTestRedis(t *testing.T) func() {
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
