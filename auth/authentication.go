package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/services/user_service"
	"ruehrstaat-backend/util"
	"strconv"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const failedAttemptCounterTTL = time.Hour
const FreshBrowserSessionMaxAge = 15 * time.Minute
const RefreshReplayRaceGracePeriod = 5 * time.Second

const (
	OTPMaxAttempts                    = 5
	OTPBlockDuration                  = 15 * time.Minute
	OTPKeyPrefix                      = "rate:otp:"
	LoginMaxAttempts                  = 5
	LoginBlockDuration                = 30 * time.Minute
	LoginKeyPrefix                    = "rate:login:"
	PasswordResetRequestMaxAttempts   = 3
	PasswordResetRequestBlockDuration = time.Hour
	PasswordResetRequestKeyPrefix     = "rate:password-reset:request:"
	RegisterMaxAttempts               = 3
	RegisterBlockDuration             = 2 * time.Hour
	RegisterKeyPrefix                 = "rate:register:"
	QuickLoginRequestMaxAttempts      = 10
	QuickLoginRequestBlockDuration    = 15 * time.Minute
	QuickLoginRequestKeyPrefix        = "rate:quicklogin:request:"
	QuickLoginMaxAttempts             = 5
	QuickLoginBlockDuration           = 15 * time.Minute
	QuickLoginKeyPrefix               = "rate:quicklogin:"
	PassiveLoginRequestMaxAttempts    = 10
	PassiveLoginRequestBlockDuration  = 15 * time.Minute
	PassiveLoginRequestKeyPrefix      = "rate:passivelogin:request:"
	PassiveLoginMaxAttempts           = 5
	PassiveLoginBlockDuration         = 15 * time.Minute
	PassiveLoginKeyPrefix             = "rate:passivelogin:"
)

func CheckUserLoginAllowance(user *entities.User) *errors.RstError {
	if !user.IsActivated {
		return ErrUserNotActivated
	}

	if user.IsBanned {
		return ErrUserBanned
	}

	return nil
}

func cappedAccessTokenExpiry(now time.Time, sessionExpiresAt time.Time) int64 {
	accessExpiresAt := now.Add(time.Hour)
	if sessionExpiresAt.Before(accessExpiresAt) {
		accessExpiresAt = sessionExpiresAt
	}
	return accessExpiresAt.Unix()
}

// Tries to login a user with the given email and password.
// Returns a token pair if successful, otherwise an error.
func Login(c *gin.Context, email string, password string, otp *string) (*TokenPair, *entities.User, *errors.RstError) {
	email = NormalizeEmail(email)
	if err := checkLoginRateLimit(c.Request.Context(), email, c.ClientIP()); err != nil {
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventLoginRateLimited, Email: email, IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent(), Success: false, ErrorReason: "rate_limited"})
		return nil, nil, err
	}

	user := &entities.User{}

	if err := FindUniqueUserByEmail(c.Request.Context(), email, user); err != nil {
		incrementLoginFailedAttempt(c.Request.Context(), email, c.ClientIP())
		if err == ErrEmailAmbiguous {
			logging.LogLoginFailed(email, c.ClientIP(), c.Request.UserAgent(), "ambiguous_email")
			return nil, nil, ErrInvalidCredentials
		}
		logging.LogLoginFailed(email, c.ClientIP(), c.Request.UserAgent(), "user_not_found")
		return nil, nil, ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		incrementLoginFailedAttempt(c.Request.Context(), email, c.ClientIP())
		logging.LogLoginFailed(email, c.ClientIP(), c.Request.UserAgent(), "invalid_password")
		return nil, nil, ErrInvalidCredentials
	}

	if currentCost, err := bcrypt.Cost([]byte(user.Password)); err == nil && currentCost < BcryptCost {
		if newHash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost); err == nil {
			previousHash := user.Password
			user.Password = string(newHash)
			_ = user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
				if lockedUser.Password != previousHash {
					return nil
				}
				lockedUser.Password = user.Password
				return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "Password")
			})
		}
	}

	if err := CheckUserLoginAllowance(user); err != nil {
		return nil, user, err
	}

	if user.HasTwoFactor() {
		if otp == nil || len(*otp) < 6 || len(*otp) > 8 {
			return nil, user, ErrUserOtpMissing
		}

		if err := checkOtpRateLimit(c.Request.Context(), user.ID.String()); err != nil {
			return nil, user, err
		}

		plainSecret := ""
		if user.OtpSecret != nil {
			if dec, err := OtpDecryptString(*user.OtpSecret); err == nil {
				plainSecret = dec
			}
		}

		if plainSecret == "" || !totp.Validate(*otp, plainSecret) {
			if err := TryBackupCodes(c, user, otp); err != nil {
				incrementOtpFailedAttempt(c.Request.Context(), user.ID.String())
				logging.Log2FAFailed(user.ID, email, c.ClientIP(), "invalid_otp")
				return nil, user, err
			}
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FABackupCodeUsed, UserID: &user.ID, Email: email, IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent(), Success: true})
		}

		resetOtpFailedAttempts(c.Request.Context(), user.ID.String())
	}

	now := time.Now()
	sessionType := entities.SessionTypeBrowser
	if isTrustedServiceRequest(c.Request) {
		sessionType = entities.SessionTypeService
	}
	session := &entities.RefreshToken{
		UserID:      user.ID,
		Token:       "",
		TokenHash:   "",
		IsRevoked:   false,
		ClientIP:    c.ClientIP(),
		UserAgent:   c.Request.UserAgent(),
		ExpiresAt:   now.Add(24 * time.Hour * 30),
		LastUsedAt:  &now,
		AuthTime:    now,
		SessionType: sessionType,
	}
	if err := db.DB.WithContext(c.Request.Context()).Create(session).Error; err != nil {
		return nil, user, errors.NewDBErrorFromError(err)
	}

	rexp := session.ExpiresAt.Unix()
	refreshToken, err := generateRefreshTokenWithSession(getRefreshTokenSecret(), user.ID.String(), session.ID, rexp)
	if err != nil {
		return nil, user, err
	}
	session.TokenHash = util.HashToken(refreshToken)
	if err := db.DB.WithContext(c.Request.Context()).Model(session).Update("token_hash", session.TokenHash).Error; err != nil {
		return nil, user, errors.NewDBErrorFromError(err)
	}

	aexp := cappedAccessTokenExpiry(now, session.ExpiresAt)
	identityToken, jti, err := generateIdentityTokenWithSession(getIdentityTokenSecret(), user.ID.String(), session.ID, aexp)
	if err != nil {
		return nil, user, err
	}
	_ = setAccessTokenAllowlist(c.Request.Context(), jti, session.ID, aexp)
	_ = db.DB.WithContext(c.Request.Context()).Create(&entities.AccessTokenJTI{UserID: user.ID, SessionID: session.ID, JTIHash: util.HashToken(jti), ExpiresAt: time.Unix(aexp, 0)}).Error

	resetLoginFailedAttempts(c.Request.Context(), email, c.ClientIP())
	addUserToSentry(user, c)
	logging.LogLoginSuccess(user.ID, email, c.ClientIP(), c.Request.UserAgent())

	tokenPair := TokenPair{RefreshToken: refreshToken, IdenityToken: identityToken, ExpiresAt: aexp, SessionID: session.ID}
	return &tokenPair, user, nil
}

func CompleteLoginWithOTP(c *gin.Context, userID string, passwordHash string, otp string) (*TokenPair, *entities.User, *errors.RstError) {
	parsedUserID, parseErr := uuid.Parse(userID)
	if parseErr != nil {
		return nil, nil, ErrInvalidState
	}

	user := &entities.User{}
	if err := db.DB.WithContext(c.Request.Context()).Where("id = ?", parsedUserID).First(user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil, ErrUserNotFound
		}
		return nil, nil, errors.NewDBErrorFromError(err)
	}
	if !loginOtpPasswordBindingMatches(user, passwordHash) {
		return nil, user, ErrInvalidState
	}

	if err := CheckUserLoginAllowance(user); err != nil {
		return nil, user, err
	}
	if !user.HasTwoFactor() {
		return nil, user, ErrInvalidCredentials
	}
	if len(otp) < 6 || len(otp) > 8 {
		return nil, user, ErrUserOtpMissing
	}
	if err := checkOtpRateLimit(c.Request.Context(), user.ID.String()); err != nil {
		return nil, user, err
	}

	plainSecret := ""
	if user.OtpSecret != nil {
		if dec, err := OtpDecryptString(*user.OtpSecret); err == nil {
			plainSecret = dec
		}
	}

	if plainSecret == "" || !totp.Validate(otp, plainSecret) {
		if err := TryBackupCodes(c, user, &otp); err != nil {
			incrementOtpFailedAttempt(c.Request.Context(), user.ID.String())
			logging.Log2FAFailed(user.ID, user.Email, c.ClientIP(), "invalid_otp")
			return nil, user, err
		}
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FABackupCodeUsed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent(), Success: true})
	}

	resetOtpFailedAttempts(c.Request.Context(), user.ID.String())
	tokenPair, err := CreateTokenPairForUser(c, user)
	if err != nil {
		return nil, user, err
	}

	addUserToSentry(user, c)
	logging.LogLoginSuccess(user.ID, user.Email, c.ClientIP(), c.Request.UserAgent())
	return tokenPair, user, nil
}

func loginOtpPasswordBindingMatches(user *entities.User, passwordHash string) bool {
	return user != nil && passwordHash != "" && user.Password == passwordHash
}

func CreateTokenPairForUser(c *gin.Context, user *entities.User) (*TokenPair, *errors.RstError) {
	now := time.Now()
	sessionType := entities.SessionTypeBrowser
	if isTrustedServiceRequest(c.Request) {
		sessionType = entities.SessionTypeService
	}
	session := &entities.RefreshToken{
		UserID:      user.ID,
		Token:       "",
		TokenHash:   "",
		IsRevoked:   false,
		ClientIP:    c.ClientIP(),
		UserAgent:   c.Request.UserAgent(),
		ExpiresAt:   now.Add(24 * time.Hour * 30),
		LastUsedAt:  &now,
		AuthTime:    now,
		SessionType: sessionType,
	}
	if err := db.DB.WithContext(c.Request.Context()).Create(session).Error; err != nil {
		return nil, errors.NewDBErrorFromError(err)
	}

	rexp := session.ExpiresAt.Unix()
	refreshToken, err := generateRefreshTokenWithSession(getRefreshTokenSecret(), user.ID.String(), session.ID, rexp)
	if err != nil {
		return nil, err
	}

	hash := util.HashToken(refreshToken)
	if err := db.DB.WithContext(c.Request.Context()).Model(session).Update("token_hash", hash).Error; err != nil {
		return nil, errors.NewDBErrorFromError(err)
	}

	aexp := cappedAccessTokenExpiry(now, session.ExpiresAt)
	identityToken, jti, err := generateIdentityTokenWithSession(getIdentityTokenSecret(), user.ID.String(), session.ID, aexp)
	if err != nil {
		return nil, err
	}
	_ = setAccessTokenAllowlist(c.Request.Context(), jti, session.ID, aexp)
	_ = db.DB.WithContext(c.Request.Context()).Create(&entities.AccessTokenJTI{UserID: user.ID, SessionID: session.ID, JTIHash: util.HashToken(jti), ExpiresAt: time.Unix(aexp, 0)}).Error

	addUserToSentry(user, c)
	return &TokenPair{RefreshToken: refreshToken, IdenityToken: identityToken, ExpiresAt: aexp, SessionID: session.ID}, nil
}

// Tries to use a backup code to do a two factor authentication.

func consumeBackupCodeFromUser(user *entities.User, otp string) bool {
	if user == nil || len(user.OtpBackupCodes) == 0 {
		return false
	}

	removeIndex := -1
	for i, stored := range user.OtpBackupCodes {
		code, err := OtpDecryptString(stored)
		if err != nil {
			continue
		}
		if code == otp {
			removeIndex = i
			break
		}
	}

	if removeIndex == -1 {
		return false
	}

	user.OtpBackupCodes = append(user.OtpBackupCodes[:removeIndex], user.OtpBackupCodes[removeIndex+1:]...)
	return true
}

func ConsumeBackupCodeFromUser(user *entities.User, otp string) bool {
	return consumeBackupCodeFromUser(user, otp)
}

func TryBackupCodes(c *gin.Context, user *entities.User, otp *string) *errors.RstError {
	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		if !consumeBackupCodeFromUser(lockedUser, *otp) {
			return ErrUserOtpWrong.Error()
		}
		user.OtpBackupCodes = lockedUser.OtpBackupCodes
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "OtpBackupCodes")
	}); err != nil {
		if err.Error() == ErrUserOtpWrong.String() {
			return ErrUserOtpWrong
		}
		return errors.NewDBErrorFromError(err)
	}

	return nil
}

// Logs out the user with the given refresh token.
// If all is true, all refresh tokens for the user will be deleted.
func Logout(c *gin.Context, refreshToken string, all bool) *errors.RstError {
	decoded, err := decodeTokenIgnoreExpiration(getRefreshTokenSecret(), refreshToken, "ruehrstaat.org")
	if err != nil {
		return err
	}

	now := time.Now()

	if all {
		existing, matched, lookupErr := findRefreshSession(db.DB.WithContext(c.Request.Context()), decoded, refreshToken, true)
		if lookupErr != nil {
			if lookupErr != gorm.ErrRecordNotFound {
				return errors.NewDBErrorFromError(lookupErr)
			}
			return ErrUsedRefreshToken
		}
		if !matched || existing.IsRevoked || !existing.ExpiresAt.After(now) || existing.SessionType != entities.SessionTypeBrowser {
			if shouldRevokeAllOnLogoutAllFailure(existing, matched, now) {
				_ = RevokeAllSessionsForUser(c.Request.Context(), decoded.Subject)
			}
			return ErrUsedRefreshToken
		}
		if err := RevokeAllSessionsForUser(c.Request.Context(), decoded.Subject); err != nil {
			return errors.NewDBErrorFromError(err)
		}
	} else {
		existing, matched, lookupErr := findRefreshSession(db.DB.WithContext(c.Request.Context()), decoded, refreshToken, false)
		if lookupErr != nil {
			if lookupErr != gorm.ErrRecordNotFound {
				return errors.NewDBErrorFromError(lookupErr)
			}
			return ErrUsedRefreshToken
		}
		if !matched {
			if !existing.IsRevoked && existing.ExpiresAt.After(now) {
				_ = RevokeAllSessionsForUser(c.Request.Context(), decoded.Subject)
			}
			return ErrUsedRefreshToken
		}
		if err := RevokeSession(c.Request.Context(), existing.ID); err != nil {
			return errors.NewDBErrorFromError(err)
		}
		logging.LogSessionRevoked(decoded.Subject, c.ClientIP(), existing.ID)
	}

	logging.LogLogout(decoded.Subject, c.ClientIP(), all)

	return nil
}

// Refreshes the access token with the given refresh token. If the refresh token is invalid, an error is returned.
// The refresh token will be rotated, so that the old one is no longer valid.
func Refresh(c *gin.Context, refreshToken string) (*TokenPair, *errors.RstError) {
	decoded, decodeErr := decodeToken(getRefreshTokenSecret(), refreshToken, "ruehrstaat.org")
	if decodeErr != nil {
		return nil, ErrUsedRefreshToken
	}

	existing := &entities.RefreshToken{}
	var newRefresh string
	var identityToken string
	var jti string
	var aexp int64
	shouldRevokeAll := false
	now := time.Now()

	txErr := db.DB.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		matched, lookupErr := findRefreshSessionForUpdate(tx, decoded, refreshToken, existing)
		if lookupErr != nil {
			if lookupErr == gorm.ErrRecordNotFound {
				return ErrUsedRefreshToken.Error()
			}
			return lookupErr
		}
		if !matched {
			shouldRevokeAll = shouldRevokeAllOnRefreshMismatch(existing, now)
			return ErrUsedRefreshToken.Error()
		}

		if existing.IsRevoked {
			shouldRevokeAll = true
			return ErrUsedRefreshToken.Error()
		}
		if existing.ExpiresAt.Unix() <= now.Unix() {
			return ErrUsedRefreshToken.Error()
		}

		user := &entities.User{}
		if err := tx.WithContext(c.Request.Context()).Where("id = ?", decoded.Subject).First(user).Error; err != nil {
			return err
		}
		if err := CheckUserLoginAllowance(user); err != nil {
			shouldRevokeAll = true
			return err.Error()
		}

		generatedRefresh, genErr := generateRefreshTokenWithSession(getRefreshTokenSecret(), decoded.Subject.String(), existing.ID, existing.ExpiresAt.Unix())
		if genErr != nil {
			return genErr.Error()
		}
		newRefresh = generatedRefresh
		aexp = cappedAccessTokenExpiry(now, existing.ExpiresAt)
		generatedIdentity, generatedJTI, genErr := generateIdentityTokenWithSession(getIdentityTokenSecret(), decoded.Subject.String(), existing.ID, aexp)
		if genErr != nil {
			return genErr.Error()
		}
		identityToken = generatedIdentity
		jti = generatedJTI

		return tx.Model(&entities.RefreshToken{}).Where("id = ?", existing.ID).Updates(map[string]any{
			"token_hash":   util.HashToken(newRefresh),
			"token":        "",
			"last_used_at": now,
			"client_ip":    c.ClientIP(),
			"user_agent":   c.Request.UserAgent(),
		}).Error
	})
	if txErr != nil {
		if shouldRevokeAll {
			_ = RevokeAllSessionsForUser(c.Request.Context(), decoded.Subject)
		}
		if txErr.Error() == ErrUsedRefreshToken.String() {
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventTokenRefreshFailed, UserID: &decoded.Subject, IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent(), Success: false, ErrorReason: "used_refresh_token"})
			return nil, ErrUsedRefreshToken
		}
		if txErr.Error() == ErrUserBanned.String() {
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventTokenRefreshFailed, UserID: &decoded.Subject, IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent(), Success: false, ErrorReason: "user_banned"})
			return nil, ErrUserBanned
		}
		return nil, errors.NewDBErrorFromError(txErr)
	}

	_ = setAccessTokenAllowlist(c.Request.Context(), jti, existing.ID, aexp)
	_ = db.DB.WithContext(c.Request.Context()).Create(&entities.AccessTokenJTI{UserID: decoded.Subject, SessionID: existing.ID, JTIHash: util.HashToken(jti), ExpiresAt: time.Unix(aexp, 0)}).Error
	logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventTokenRefresh, UserID: &decoded.Subject, IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent(), Success: true, Details: map[string]any{"session_id": existing.ID.String()}})

	return &TokenPair{RefreshToken: newRefresh, IdenityToken: identityToken, ExpiresAt: aexp, SessionID: existing.ID}, nil
}

func refreshTokenMatchesSession(session *entities.RefreshToken, refreshToken string, refreshHash string) bool {
	if session == nil {
		return false
	}
	return session.TokenHash != "" && session.TokenHash == refreshHash
}

func findRefreshSessionForUpdate(tx *gorm.DB, decoded *decodedToken, refreshToken string, existing *entities.RefreshToken) (bool, error) {
	lockedTx := tx.Clauses(clause.Locking{Strength: "UPDATE"})
	session, matched, err := findRefreshSession(lockedTx, decoded, refreshToken, true)
	if err != nil {
		return false, err
	}
	*existing = *session
	return matched, nil
}

func findRefreshSession(tx *gorm.DB, decoded *decodedToken, refreshToken string, preferSessionID bool) (*entities.RefreshToken, bool, error) {
	refreshHash := util.HashToken(refreshToken)
	if preferSessionID && decoded.SID != uuid.Nil {
		existing := &entities.RefreshToken{}
		if res := tx.Where("id = ? AND user_id = ?", decoded.SID, decoded.Subject).First(existing); res.Error != nil {
			return nil, false, res.Error
		}
		return existing, refreshTokenMatchesSession(existing, refreshToken, refreshHash), nil
	}

	existing := &entities.RefreshToken{}
	if res := tx.Where("user_id = ? AND token_hash = ?", decoded.Subject, refreshHash).First(existing); res.Error != nil {
		return nil, false, res.Error
	}
	return existing, true, nil
}

func extractBearerIdentityToken(ctx *gin.Context) string {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.Fields(authHeader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return parts[1]
}

func decodeBearerIdentityToken(ctx *gin.Context) (*decodedToken, *errors.RstError) {
	identityToken := extractBearerIdentityToken(ctx)
	if identityToken == "" {
		return nil, ErrInvalidToken
	}

	decoded, err := decodeToken(getIdentityTokenSecret(), identityToken, "ruehrstaat.org")
	if err != nil {
		return nil, err
	}

	if decoded.JTI == "" || decoded.SID == uuid.Nil {
		return nil, ErrInvalidToken
	}

	if ok := checkAccessTokenAllowlist(ctx.Request.Context(), decoded.JTI, decoded.SID, decoded.Subject); !ok {
		return nil, ErrInvalidToken
	}

	return decoded, nil
}

func loadAuthorizedUser(ctx *gin.Context, userID uuid.UUID) (*entities.User, *errors.RstError) {
	user := &entities.User{}
	if res := db.DB.WithContext(ctx.Request.Context()).Where("id = ?", userID).First(user); res.Error != nil {
		return nil, ErrInvalidToken
	}
	if err := CheckUserLoginAllowance(user); err != nil {
		return nil, err
	}

	addUserToSentry(user, ctx)
	return user, nil
}

func RequireSessionBoundAuth(ctx *gin.Context) (*entities.User, *errors.RstError) {
	if allowsBearerOnlyNonBrowserRequest(ctx.Request) {
		decoded, err := decodeBearerIdentityToken(ctx)
		if err != nil {
			return nil, ErrUnauthorized
		}

		session, _, sessionErr := findRefreshSession(db.DB.WithContext(ctx.Request.Context()), decoded, "", true)
		if sessionErr != nil || !isActiveServiceSession(session, time.Now()) {
			return nil, ErrUnauthorized
		}

		user, userErr := loadAuthorizedUser(ctx, decoded.Subject)
		if userErr != nil {
			return nil, ErrUnauthorized
		}

		return user, nil
	}

	if err := ValidateCookieAuthRequest(ctx.Request); err != nil {
		return nil, err
	}

	decoded, err := decodeBearerIdentityToken(ctx)
	if err != nil {
		return nil, ErrUnauthorized
	}

	refreshDecoded, _, sessionErr := requireCurrentBrowserSession(ctx)
	if sessionErr != nil {
		return nil, sessionErr
	}
	if refreshDecoded.Subject != decoded.Subject || refreshDecoded.SID != decoded.SID {
		return nil, ErrUnauthorized
	}

	user, userErr := loadAuthorizedUser(ctx, decoded.Subject)
	if userErr != nil {
		return nil, ErrUnauthorized
	}

	return user, nil
}

func RequireCurrentBrowserSession(ctx *gin.Context) (*entities.User, *entities.RefreshToken, *errors.RstError) {
	decoded, session, err := requireCurrentBrowserSession(ctx)
	if err != nil {
		return nil, nil, err
	}

	user, userErr := loadAuthorizedUser(ctx, decoded.Subject)
	if userErr != nil {
		return nil, nil, ErrUnauthorized
	}

	return user, session, nil
}

func RequireFreshBrowserSession(ctx *gin.Context) (*entities.User, *entities.RefreshToken, *errors.RstError) {
	user, session, err := RequireCurrentBrowserSession(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !hasRecentBrowserSessionAuthTime(session.AuthTime, time.Now()) {
		return nil, nil, ErrRecentAuthenticationRequired
	}

	return user, session, nil
}

func requireCurrentBrowserSession(ctx *gin.Context) (*decodedToken, *entities.RefreshToken, *errors.RstError) {
	if err := ValidateCookieAuthRequest(ctx.Request); err != nil {
		return nil, nil, err
	}

	refreshToken, cookieErr := ctx.Cookie("refresh_token")
	if cookieErr != nil {
		return nil, nil, ErrUnauthorized
	}

	refreshDecoded, decodeErr := decodeToken(getRefreshTokenSecret(), refreshToken, "ruehrstaat.org")
	if decodeErr != nil || refreshDecoded.SID == uuid.Nil {
		return nil, nil, ErrUnauthorized
	}

	session, matched, sessionErr := findRefreshSession(db.DB.WithContext(ctx.Request.Context()), refreshDecoded, refreshToken, true)
	if sessionErr != nil || !matched {
		return nil, nil, ErrUnauthorized
	}
	if session.IsRevoked || !session.ExpiresAt.After(time.Now()) || session.SessionType != entities.SessionTypeBrowser {
		return nil, nil, ErrUnauthorized
	}

	return refreshDecoded, session, nil
}

func isActiveServiceSession(session *entities.RefreshToken, now time.Time) bool {
	return session != nil && !session.IsRevoked && session.ExpiresAt.After(now) && session.SessionType == entities.SessionTypeService
}

func hasRecentBrowserSessionAuthTime(authTime time.Time, now time.Time) bool {
	if authTime.IsZero() {
		return false
	}
	return authTime.Add(FreshBrowserSessionMaxAge).After(now)
}

func shouldRevokeAllOnRefreshMismatch(session *entities.RefreshToken, now time.Time) bool {
	if session == nil || session.IsRevoked || !session.ExpiresAt.After(now) {
		return false
	}
	if session.LastUsedAt == nil {
		return true
	}
	return session.LastUsedAt.Add(RefreshReplayRaceGracePeriod).Before(now)
}

func shouldRevokeAllOnLogoutAllFailure(session *entities.RefreshToken, matched bool, now time.Time) bool {
	if !matched {
		return shouldRevokeAllOnRefreshMismatch(session, now)
	}
	return session != nil && !session.IsRevoked && session.ExpiresAt.After(now)
}

func rateLimitIdentifierWithClientIP(identifier string, clientIP string) string {
	trimmedIdentifier := strings.TrimSpace(identifier)
	trimmedIP := strings.TrimSpace(clientIP)
	if parsedIP := net.ParseIP(trimmedIP); parsedIP != nil {
		trimmedIP = parsedIP.String()
	}
	if trimmedIP == "" {
		trimmedIP = "unknown"
	}
	return trimmedIdentifier + "|ip:" + trimmedIP
}

// Extracts the user from the given context by extracting the token from the Authorization header.
func Extract(ctx *gin.Context) *entities.User {
	decoded, err := decodeBearerIdentityToken(ctx)
	if err != nil {
		return nil
	}
	user, userErr := loadAuthorizedUser(ctx, decoded.Subject)
	if userErr != nil {
		return nil
	}

	return user
}

func addUserToSentry(user *entities.User, ctx *gin.Context) {
	hub := sentry.GetHubFromContext(ctx.Request.Context())
	if hub != nil {
		hub.Scope().SetUser(sentry.User{ID: user.ID.String(), Email: user.Email, IPAddress: ctx.ClientIP(), Username: fmt.Sprintf("%s/%s", user.Nickname, user.CmdrName)})
	}
}

func checkOtpRateLimit(c context.Context, userID string) *errors.RstError {
	return checkRateLimit(c, OTPKeyPrefix, userID, OTPMaxAttempts, OTPBlockDuration, ErrUserOtpRateLimited)
}

func CheckOtpRateLimit(c context.Context, userID string) *errors.RstError {
	return checkOtpRateLimit(c, userID)
}

func incrementOtpFailedAttempt(c context.Context, userID string) {
	incrementFailedAttempt(c, OTPKeyPrefix, userID, OTPMaxAttempts, OTPBlockDuration)
}

func IncrementOtpFailedAttempt(c context.Context, userID string) {
	incrementOtpFailedAttempt(c, userID)
}

func resetOtpFailedAttempts(c context.Context, userID string) {
	resetFailedAttempts(c, OTPKeyPrefix, userID)
}

func ResetOtpFailedAttempts(c context.Context, userID string) {
	resetOtpFailedAttempts(c, userID)
}

func checkLoginRateLimit(c context.Context, email string, clientIP string) *errors.RstError {
	return checkRateLimit(c, LoginKeyPrefix, rateLimitIdentifierWithClientIP(email, clientIP), LoginMaxAttempts, LoginBlockDuration, ErrLoginRateLimited)
}

func incrementLoginFailedAttempt(c context.Context, email string, clientIP string) {
	incrementFailedAttempt(c, LoginKeyPrefix, rateLimitIdentifierWithClientIP(email, clientIP), LoginMaxAttempts, LoginBlockDuration)
}

func resetLoginFailedAttempts(c context.Context, email string, clientIP string) {
	resetFailedAttempts(c, LoginKeyPrefix, rateLimitIdentifierWithClientIP(email, clientIP))
}

func CheckAndIncrementPasswordResetRequestRateLimit(c context.Context, email string, clientIP string) *errors.RstError {
	email = NormalizeEmail(email)
	if err := checkPasswordResetRequestRateLimit(c, email, clientIP); err != nil {
		return err
	}
	incrementPasswordResetRequestAttempt(c, email, clientIP)
	return nil
}

func checkPasswordResetRequestRateLimit(c context.Context, email string, clientIP string) *errors.RstError {
	return checkRateLimit(c, PasswordResetRequestKeyPrefix, rateLimitIdentifierWithClientIP(email, clientIP), PasswordResetRequestMaxAttempts, PasswordResetRequestBlockDuration, ErrPasswordResetRateLimited)
}

func incrementPasswordResetRequestAttempt(c context.Context, email string, clientIP string) {
	incrementFailedAttempt(c, PasswordResetRequestKeyPrefix, rateLimitIdentifierWithClientIP(email, clientIP), PasswordResetRequestMaxAttempts, PasswordResetRequestBlockDuration)
}

func checkRegistrationRateLimit(c context.Context, email string) *errors.RstError {
	return checkRateLimit(c, RegisterKeyPrefix, email, RegisterMaxAttempts, RegisterBlockDuration, ErrRegistrationRateLimited)
}

func checkQuickLoginRateLimit(c context.Context, userID string) *errors.RstError {
	return checkRateLimit(c, QuickLoginKeyPrefix, userID, QuickLoginMaxAttempts, QuickLoginBlockDuration, ErrQuickloginRateLimited)
}

func checkQuickLoginRequestRateLimit(c context.Context, clientIP string) *errors.RstError {
	return checkRateLimit(c, QuickLoginRequestKeyPrefix, clientIP, QuickLoginRequestMaxAttempts, QuickLoginRequestBlockDuration, ErrQuickloginRequestRateLimited)
}

func checkPassiveLoginRequestRateLimit(c context.Context, clientIP string) *errors.RstError {
	return checkRateLimit(c, PassiveLoginRequestKeyPrefix, clientIP, PassiveLoginRequestMaxAttempts, PassiveLoginRequestBlockDuration, ErrPassiveLoginRequestRateLimited)
}

func checkPassiveLoginRateLimit(c context.Context, userID string) *errors.RstError {
	return checkRateLimit(c, PassiveLoginKeyPrefix, userID, PassiveLoginMaxAttempts, PassiveLoginBlockDuration, ErrPassiveLoginRateLimited)
}

func incrementRegistrationFailedAttempt(c context.Context, email string) {
	incrementFailedAttempt(c, RegisterKeyPrefix, email, RegisterMaxAttempts, RegisterBlockDuration)
}

func incrementQuickLoginFailedAttempt(c context.Context, userID string) {
	incrementFailedAttempt(c, QuickLoginKeyPrefix, userID, QuickLoginMaxAttempts, QuickLoginBlockDuration)
}

func incrementQuickLoginRequestAttempt(c context.Context, clientIP string) {
	incrementFailedAttempt(c, QuickLoginRequestKeyPrefix, clientIP, QuickLoginRequestMaxAttempts, QuickLoginRequestBlockDuration)
}

func incrementPassiveLoginRequestAttempt(c context.Context, clientIP string) {
	incrementFailedAttempt(c, PassiveLoginRequestKeyPrefix, clientIP, PassiveLoginRequestMaxAttempts, PassiveLoginRequestBlockDuration)
}

func incrementPassiveLoginFailedAttempt(c context.Context, userID string) {
	incrementFailedAttempt(c, PassiveLoginKeyPrefix, userID, PassiveLoginMaxAttempts, PassiveLoginBlockDuration)
}

func resetRegistrationFailedAttempts(c context.Context, email string) {
	resetFailedAttempts(c, RegisterKeyPrefix, email)
}

func resetQuickLoginFailedAttempts(c context.Context, userID string) {
	resetFailedAttempts(c, QuickLoginKeyPrefix, userID)
}

func resetPassiveLoginFailedAttempts(c context.Context, userID string) {
	resetFailedAttempts(c, PassiveLoginKeyPrefix, userID)
}

func checkRateLimit(c context.Context, keyPrefix string, identifier string, maxAttempts int, blockDuration time.Duration, rateLimitError *errors.RstError) *errors.RstError {
	if cache.Redis == nil {
		return nil
	}

	key := keyPrefix + identifier
	blocked, err := cache.Redis.Get(c, key+":blocked").Result()
	if err == nil && blocked == "1" {
		return rateLimitError
	}

	attempts, err := cache.Redis.Get(c, key).Result()
	if err == nil {
		count, _ := strconv.Atoi(attempts)
		if count >= maxAttempts {
			return rateLimitError
		}
	}

	return nil
}

func incrementFailedAttempt(c context.Context, keyPrefix string, identifier string, maxAttempts int, blockDuration time.Duration) {
	if cache.Redis == nil {
		return
	}

	key := keyPrefix + identifier
	count, err := cache.Redis.Incr(c, key).Result()
	if err != nil {
		return
	}
	if count == 1 {
		_ = cache.Redis.Expire(c, key, failedAttemptCounterTTL).Err()
	}
	if count >= int64(maxAttempts) {
		_ = cache.Redis.Set(c, key+":blocked", "1", blockDuration).Err()
	}
}

func resetFailedAttempts(c context.Context, keyPrefix string, identifier string) {
	if cache.Redis == nil {
		return
	}

	key := keyPrefix + identifier
	_ = cache.Redis.Del(c, key, key+":blocked").Err()
}

func isTrustedServiceRequest(r *http.Request) bool {
	return r != nil && isServiceUserAgent(r.UserAgent()) && requestComesFromTrustedProxy(r)
}

func isServiceUserAgent(ua string) bool {
	return strings.TrimSpace(ua) == "cloudflare-access"
}
