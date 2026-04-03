package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"ruehrstaat-backend/util"
)

const otpEncPrefix = "enc:"

func OtpEncryptionEnabled() bool {
	key := util.ParseOptionalAESKey("OTP_ENC_KEY")
	return len(key) == 16 || len(key) == 24 || len(key) == 32
}

func OtpIsEncrypted(stored string) bool {
	return len(stored) >= len(otpEncPrefix) && stored[:len(otpEncPrefix)] == otpEncPrefix
}

func OtpEncryptString(plain string) (string, error) {
	otpEncKey, err := util.ParseRequiredAESKey("OTP_ENC_KEY")
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(otpEncKey)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nil, nonce, []byte(plain), nil)
	buf := append(nonce, ciphertext...)
	return otpEncPrefix + base64.StdEncoding.EncodeToString(buf), nil
}

func OtpDecryptString(stored string) (string, error) {
	if len(stored) == 0 || !OtpIsEncrypted(stored) {
		return stored, nil
	}

	otpEncKey, err := util.ParseRequiredAESKey("OTP_ENC_KEY")
	if err != nil {
		return "", err
	}

	enc := stored[len(otpEncPrefix):]
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(otpEncKey)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(raw) < aead.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce := raw[:aead.NonceSize()]
	ciphertext := raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}
