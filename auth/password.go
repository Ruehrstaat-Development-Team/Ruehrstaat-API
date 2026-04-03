package auth

import (
	"unicode"

	"ruehrstaat-backend/errors"
)

const BcryptCost = 12

func validatePasswordStrength(password string) *errors.RstError {
	if len(password) < 10 {
		return ErrPasswordTooWeak
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsNumber(c):
			hasNumber = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return ErrPasswordTooWeak
	}

	return nil
}
