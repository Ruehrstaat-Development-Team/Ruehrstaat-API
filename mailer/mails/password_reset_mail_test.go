package mails

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPasswordResetMailUsesRetFragmentParameter(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://frontend.example")

	body := PasswordResetMail{
		UserID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Ref:    "opaque-ref",
		Totp:   true,
	}.GetBody("en")

	if !strings.Contains(body, "#ret=opaque-ref&totp=true") {
		t.Fatalf("password reset body missing ret fragment parameter: %q", body)
	}

	if !strings.Contains(body, "https://frontend.example/en/reset-password/11111111-1111-1111-1111-111111111111") {
		t.Fatalf("password reset body missing localized frontend path: %q", body)
	}

	if strings.Contains(body, "?ret=") {
		t.Fatalf("password reset body still contains ret query parameter: %q", body)
	}
}
