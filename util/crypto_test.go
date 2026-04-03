package util

import (
	"encoding/base64"
	"testing"
)

func TestParseOptionalAESKey(t *testing.T) {
	t.Run("loads raw key from environment", func(t *testing.T) {
		expected := "12345678901234567890123456789012"
		t.Setenv("TEST_AES_KEY", expected)
		if got := string(ParseOptionalAESKey("TEST_AES_KEY")); got != expected {
			t.Fatalf("ParseOptionalAESKey() = %q, want %q", got, expected)
		}
	})

	t.Run("loads base64 encoded key from environment", func(t *testing.T) {
		expected := []byte("1234567890123456")
		t.Setenv("TEST_AES_KEY", base64.StdEncoding.EncodeToString(expected))
		if got := ParseOptionalAESKey("TEST_AES_KEY"); string(got) != string(expected) {
			t.Fatalf("ParseOptionalAESKey() = %q, want %q", string(got), string(expected))
		}
	})

	t.Run("invalid key returns nil", func(t *testing.T) {
		t.Setenv("TEST_AES_KEY", "short")
		if got := ParseOptionalAESKey("TEST_AES_KEY"); got != nil {
			t.Fatalf("ParseOptionalAESKey() = %v, want nil", got)
		}
	})
}

func TestParseRequiredAESKey(t *testing.T) {
	t.Run("missing key returns error", func(t *testing.T) {
		t.Setenv("TEST_AES_KEY", "")
		if _, err := ParseRequiredAESKey("TEST_AES_KEY"); err == nil {
			t.Fatal("ParseRequiredAESKey() error = nil, want error")
		}
	})

	t.Run("invalid key returns error", func(t *testing.T) {
		t.Setenv("TEST_AES_KEY", "short")
		if _, err := ParseRequiredAESKey("TEST_AES_KEY"); err == nil {
			t.Fatal("ParseRequiredAESKey() error = nil, want error")
		}
	})
}

func TestFidoDecryptStringFailsClosedWithoutKey(t *testing.T) {
	t.Setenv("FIDO_ENC_KEY", "")

	if _, err := FidoDecryptString("fenc:Zm9v"); err == nil {
		t.Fatal("FidoDecryptString() error = nil, want error")
	}
}

func TestFidoEncryptStringRequiresKey(t *testing.T) {
	t.Setenv("FIDO_ENC_KEY", "")

	if _, err := FidoEncryptString("secret"); err == nil {
		t.Fatal("FidoEncryptString() error = nil, want error")
	}
}
