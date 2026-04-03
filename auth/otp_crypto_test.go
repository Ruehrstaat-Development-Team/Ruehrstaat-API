package auth

import (
	"testing"

	"ruehrstaat-backend/db/entities"

	"github.com/lib/pq"
)

func TestOtpEncryptStringRequiresKey(t *testing.T) {
	t.Setenv("OTP_ENC_KEY", "")

	if _, err := OtpEncryptString("secret"); err == nil {
		t.Fatal("OtpEncryptString() error = nil, want error")
	}
}

func TestOtpDecryptStringFailsClosedWithoutKey(t *testing.T) {
	t.Setenv("OTP_ENC_KEY", "")

	if _, err := OtpDecryptString("enc:Zm9v"); err == nil {
		t.Fatal("OtpDecryptString() error = nil, want error")
	}
}

func TestConsumeBackupCodeFromUserSkipsUndecryptableEncryptedCodes(t *testing.T) {
	t.Setenv("OTP_ENC_KEY", "")

	user := &entities.User{OtpBackupCodes: pq.StringArray{"enc:Zm9v"}}
	if consumeBackupCodeFromUser(user, "foo") {
		t.Fatal("consumeBackupCodeFromUser() = true, want false")
	}
	if len(user.OtpBackupCodes) != 1 {
		t.Fatalf("backup code count = %d, want 1", len(user.OtpBackupCodes))
	}
}
