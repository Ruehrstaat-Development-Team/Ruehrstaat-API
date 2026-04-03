package mails

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestActivationMailUsesFragmentParameter(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://frontend.example")

	body := ActivationMail{
		UserID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Ref:    "opaque-ref",
	}.GetBody("en")

	if !strings.Contains(body, "#activation=opaque-ref") {
		t.Fatalf("activation mail missing fragment parameter: %q", body)
	}

	if !strings.Contains(body, "https://frontend.example/en/activate/11111111-1111-1111-1111-111111111111") {
		t.Fatalf("activation mail missing localized frontend path: %q", body)
	}

	if strings.Contains(body, "?activation=") {
		t.Fatalf("activation mail still contains query parameter: %q", body)
	}
}

func TestChangeEmailMailUsesFragmentParameter(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://frontend.example")

	body := ChangeEmailMail{
		UserID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Ref:    "opaque-ref",
	}.GetBody("en")

	if !strings.Contains(body, "#ect=opaque-ref") {
		t.Fatalf("change email mail missing fragment parameter: %q", body)
	}

	if !strings.Contains(body, "https://frontend.example/en/changeMail/11111111-1111-1111-1111-111111111111") {
		t.Fatalf("change email mail missing localized frontend path: %q", body)
	}

	if strings.Contains(body, "?ect=") {
		t.Fatalf("change email mail still contains query parameter: %q", body)
	}
}

func TestActivationMailUsesUserLocaleInFrontendPath(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://frontend.example/app")

	body := ActivationMail{
		UserID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Ref:    "opaque-ref",
	}.GetBody("de")

	if !strings.Contains(body, "https://frontend.example/app/de/activate/11111111-1111-1111-1111-111111111111#activation=opaque-ref") {
		t.Fatalf("activation mail missing locale-prefixed path: %q", body)
	}
}
