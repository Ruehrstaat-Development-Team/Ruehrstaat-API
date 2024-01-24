package util

import (
	"crypto/rand"
	"math/big"
)

func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	return generateRandomStringFromCharset(n, letters)
}

func GenerateReadableRandomString(n int) (string, error) {
	// Excludes characters like 0, O, l, I, 1, etc.
	const letters = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
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
