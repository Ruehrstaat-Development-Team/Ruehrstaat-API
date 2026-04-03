package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"ruehrstaat-backend/cache"
)

const frontendTokenReferencePrefix = "lref:"

func createFrontendTokenReference(category string, token string) string {
	key := sha256.Sum256([]byte(getIdentityTokenSecret() + ":frontend-link-ref:" + category))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	ciphertext := aead.Seal(nil, nonce, []byte(token), []byte(category))
	payload := append(nonce, ciphertext...)
	return frontendTokenReferencePrefix + base64.RawURLEncoding.EncodeToString(payload)
}

func resolveFrontendTokenReference(category string, value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= len(frontendTokenReferencePrefix) || value[:len(frontendTokenReferencePrefix)] != frontendTokenReferencePrefix {
		if cache.Redis == nil {
			return ""
		}
		var token string
		if cache.GetState(category, value, &token) {
			return token
		}
		return ""
	}

	key := sha256.Sum256([]byte(getIdentityTokenSecret() + ":frontend-link-ref:" + category))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return ""
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}

	raw, err := base64.RawURLEncoding.DecodeString(value[len(frontendTokenReferencePrefix):])
	if err != nil || len(raw) < aead.NonceSize() {
		return ""
	}

	nonce := raw[:aead.NonceSize()]
	ciphertext := raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(category))
	if err != nil {
		return ""
	}

	return string(plain)
}

func deleteFrontendTokenReference(category string, value string) {
	if value == "" || (len(value) > len(frontendTokenReferencePrefix) && value[:len(frontendTokenReferencePrefix)] == frontendTokenReferencePrefix) {
		return
	}
	if cache.Redis == nil {
		return
	}

	cache.DeleteState(category, value)
}
