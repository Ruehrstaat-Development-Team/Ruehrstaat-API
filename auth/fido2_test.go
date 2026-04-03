package auth

import (
	"testing"

	"ruehrstaat-backend/db/entities"

	"github.com/google/uuid"
)

func TestParseFido2UserHandleAllowsColonInDisplayName(t *testing.T) {
	login := &entities.Fido2Login{UserID: uuid.New(), DisplayName: "Laptop:Chrome"}

	userID, displayName, err := parseFido2UserHandle(login.WebAuthnID())
	if err != nil {
		t.Fatalf("parseFido2UserHandle() error = %v, want nil", err)
	}
	if userID != login.UserID {
		t.Fatalf("parseFido2UserHandle() userID = %s, want %s", userID, login.UserID)
	}
	if displayName != login.DisplayName {
		t.Fatalf("parseFido2UserHandle() displayName = %q, want %q", displayName, login.DisplayName)
	}
}

func TestParseFido2UserHandleRejectsInvalidFormat(t *testing.T) {
	if _, _, err := parseFido2UserHandle([]byte("not-a-valid-handle")); err != ErrInvalidUserHandle {
		t.Fatalf("parseFido2UserHandle() error = %v, want %v", err, ErrInvalidUserHandle)
	}
}
