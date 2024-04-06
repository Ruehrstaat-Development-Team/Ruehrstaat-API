package auth

import "errors"

var (
	ErrAbsoluteExpReached     = errors.New("absolute expiration reached")
	ErrInvalidSigningMethod   = errors.New("invalid signing method")
	ErrInvalidToken           = errors.New("invalid token")
	ErrInvalidEmail           = errors.New("invalid email")
	ErrEmailTaken             = errors.New("email taken")
	ErrUserNotFound           = errors.New("user not found")
	ErrUserNotActivated       = errors.New("user not activated")
	ErrUserBanned             = errors.New("user banned")
	ErrUserOtpMissing         = errors.New("user otp missing")
	ErrUserOtpWrong           = errors.New("user otp wrong")
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrUsedRefreshToken       = errors.New("used refresh token")
	ErrInvalidActivationToken = errors.New("invalid activation token")
	ErrUserAlreadyActivated   = errors.New("user already activated")
	ErrInvalidResetToken      = errors.New("invalid reset token")
	ErrResetNotRequested      = errors.New("reset not requested")
	ErrForbidden              = errors.New("forbidden")
	ErrInvalidUUID            = errors.New("invalid uuid")

	ErrInvalidEmailChangeToken = errors.New("invalid email change token")
	ErrEmailChangeNotRequested = errors.New("email change not requested")

	ErrUnauthorized = errors.New("unauthorized")

	ErrServer = errors.New("server error")
)
