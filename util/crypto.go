package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
)

const fidoEncPrefix = "fenc:"

func ParseOptionalAESKey(envName string) []byte {
	key := os.Getenv(envName)
	if len(key) == 0 {
		return nil
	}

	if len(key) == 32 {
		return []byte(key)
	}

	if decoded, err := base64.StdEncoding.DecodeString(key); err == nil && (len(decoded) == 16 || len(decoded) == 24 || len(decoded) == 32) {
		return decoded
	}

	return nil
}

func ParseRequiredAESKey(envName string) ([]byte, error) {
	key := os.Getenv(envName)
	if len(key) == 0 {
		return nil, errors.New("missing encryption key")
	}

	parsed := ParseOptionalAESKey(envName)
	if len(parsed) == 0 {
		return nil, errors.New("invalid encryption key")
	}

	return parsed, nil
}

func FidoEncryptionEnabled() bool {
	key := ParseOptionalAESKey("FIDO_ENC_KEY")
	return len(key) == 16 || len(key) == 24 || len(key) == 32
}

func FidoIsEncrypted(s string) bool {
	return len(s) >= len(fidoEncPrefix) && s[:len(fidoEncPrefix)] == fidoEncPrefix
}

func FidoEncryptString(plain string) (string, error) {
	fidoEncKey, err := ParseRequiredAESKey("FIDO_ENC_KEY")
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(fidoEncKey)
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
	return fidoEncPrefix + base64.StdEncoding.EncodeToString(buf), nil
}

func FidoDecryptString(stored string) (string, error) {
	if len(stored) == 0 || !FidoIsEncrypted(stored) {
		return stored, nil
	}

	fidoEncKey, err := ParseRequiredAESKey("FIDO_ENC_KEY")
	if err != nil {
		return "", err
	}

	enc := stored[len(fidoEncPrefix):]
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(fidoEncKey)
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

func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	return generateRandomStringFromCharset(n, letters)
}

func GenerateReadableRandomString(n int) (string, error) {
	// Excludes characters like 0, O, l, I, 1, etc.
	const letters = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	return generateRandomStringFromCharset(n, letters)
}

// Generate randoim number string
func GenerateRandomNumberString(n int) (string, error) {
	const letters = "0123456789"
	return generateRandomStringFromCharset(n, letters)
}

func generateRandomStringFromCharset(n int, charset string) (string, error) {
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		ret[i] = charset[num.Int64()]
	}

	return string(ret), nil
}
