package auth

import "ruehrstaat-backend/errors"

var (
	ErrPackageAuth = errors.NewPackage("Authentication", "Auth")
)

// codes
// 1xxx - invalid something
// 2xxx - not found
// 3xxx - already done / exists
// 4xxx - forbidden
// 5xxx - server error

// 9xxx - other
// 9999 - unknown error

var (
	ErrInvalidToken            = errors.New(1001, *ErrPackageAuth, 401, "", "Invalid token")
	ErrInvalidEmail            = errors.New(1002, *ErrPackageAuth, 400, "", "Invalid email")
	ErrInvalidActivationToken  = errors.New(1003, *ErrPackageAuth, 400, "", "Invalid activation token")
	ErrInvalidResetToken       = errors.New(1004, *ErrPackageAuth, 400, "", "Invalid reset token")
	ErrInvalidUUID             = errors.New(1005, *ErrPackageAuth, 400, "", "Invalid uuid")
	ErrInvalidEmailChangeToken = errors.New(1006, *ErrPackageAuth, 400, "", "Invalid email change token")
	ErrInvalidState            = errors.New(1007, *ErrPackageAuth, 400, "", "Invalid state")
	ErrInvalidSession          = errors.New(1008, *ErrPackageAuth, 400, "", "Invalid session")
	ErrInvalidUserHandle       = errors.New(1009, *ErrPackageAuth, 400, "", "Invalid user handle")

	ErrInvalidSigningMethod = errors.New(1901, *ErrPackageAuth, 500, "", "Invalid signing method")

	ErrUserNotFound            = errors.New(2001, *ErrPackageAuth, 404, "", "User not found")
	ErrUserNotActivated        = errors.New(2002, *ErrPackageAuth, 428, "", "User not activated")
	ErrUserOtpMissing          = errors.New(2003, *ErrPackageAuth, 428, "", "User otp missing")
	ErrResetNotRequested       = errors.New(2004, *ErrPackageAuth, 400, "", "Reset not requested")
	ErrEmailChangeNotRequested = errors.New(2005, *ErrPackageAuth, 400, "", "Email change not requested")
	ErrRedirectUrlMissing      = errors.New(2006, *ErrPackageAuth, 400, "", "Redirect url missing")
	ErrStateIsMissing          = errors.New(2007, *ErrPackageAuth, 400, "", "State is missing")
	ErrCodeIsMissing           = errors.New(2008, *ErrPackageAuth, 400, "", "Code is missing")

	ErrEmailTaken           = errors.New(3001, *ErrPackageAuth, 400, "", "Email taken")
	ErrUserAlreadyActivated = errors.New(3002, *ErrPackageAuth, 409, "", "User already activated")

	ErrForbidden                        = errors.New(4000, *ErrPackageAuth, 403, "", "Forbidden")
	ErrUnauthorized                     = errors.New(4001, *ErrPackageAuth, 401, "", "Unauthorized")
	ErrUserBanned                       = errors.New(4002, *ErrPackageAuth, 403, "", "User banned")
	ErrUserOtpWrong                     = errors.New(4003, *ErrPackageAuth, 403, "", "User otp wrong")
	ErrInvalidCredentials               = errors.NewWithInternalMessage(4004, *ErrPackageAuth, 403, "", "Invalid credentials", "In sentry additional error above might be attached")
	ErrUserNotFoundOrInvalidCredentials = errors.NewWithInternalMessage(4005, *ErrPackageAuth, 404, "", "User not found or invalid credentials", "In sentry see above error for more details.")

	ErrServer                          = errors.New(5001, *ErrPackageAuth, 500, "", "Internal server error")
	ErrQuickloginTokenRequestFailed    = errors.NewWithInternalMessage(5002, *ErrPackageAuth, 400, "", "Could not request quicklogin token", "In sentry see above error for more details.")
	ErrQuickloginTokenValidationFailed = errors.NewWithInternalMessage(5003, *ErrPackageAuth, 400, "", "Could not validate quicklogin token", "In sentry see above error for more details.")
	ErrQuickloginCompletionFailed      = errors.NewWithInternalMessage(5004, *ErrPackageAuth, 400, "", "Could not complete quicklogin", "In sentry see above error for more details.")

	ErrAbsoluteExpReached   = errors.New(9001, *ErrPackageAuth, 401, "", "Absolute expiration reached")
	ErrUsedRefreshToken     = errors.New(9002, *ErrPackageAuth, 400, "", "Used refresh token")
	ErrRegistrationDisabled = errors.New(9003, *ErrPackageAuth, 403, "", "Registration is disabled")
)
