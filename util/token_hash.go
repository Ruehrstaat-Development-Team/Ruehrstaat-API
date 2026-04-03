package util

import (
	"crypto/sha512"
	"encoding/hex"
)

func HashToken(token string) string {
	sum := sha512.Sum512([]byte(token))
	return hex.EncodeToString(sum[:])
}
