package users

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/services/user_service"
	"ruehrstaat-backend/util"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

func beginTotp(c *gin.Context) {
	user, _, authErr := auth.RequireFreshBrowserSession(c)
	if authErr != nil {
		c.Error(authErr.Error())
		errors.ReturnWithError(c, authErr)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Ruehrstaat-Squadron",
		AccountName: user.Email,
	})
	if err != nil {
		c.Error(err)
		panic(err)
	}

	secret := key.Secret()
	encryptedSecret, err := auth.OtpEncryptString(secret)
	if err != nil {
		c.Error(err)
		panic(err)
	}

	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		if lockedUser.OtpActive {
			return auth.ErrOTPAlreadySet.Error()
		}
		lockedUser.OtpSecret = &encryptedSecret
		lockedUser.OtpActive = true
		user.OtpSecret = &encryptedSecret
		user.OtpActive = true
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "OtpSecret", "OtpActive")
	}); err != nil {
		if err.Error() == auth.ErrOTPAlreadySet.String() {
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FAFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "already_enabled", Details: map[string]any{"action": "begin_totp"}})
			errors.ReturnWithError(c, auth.ErrOTPAlreadySet)
			return
		}
		c.Error(err)
		panic(err)
	}

	c.JSON(200, gin.H{"url": key.String()})
}

func verifyTotp(c *gin.Context) {
	user, _, authErr := auth.RequireFreshBrowserSession(c)
	if authErr != nil {
		c.Error(authErr.Error())
		errors.ReturnWithError(c, authErr)
		return
	}

	dto := &struct {
		Code string `json:"code" binding:"required"`
	}{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	plainCodes, storedCodes := generateRecoveryCodes(10)
	err := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		if !lockedUser.OtpActive {
			return auth.ErrOTPIsNotSet.Error()
		}
		if lockedUser.OtpVerified {
			return auth.ErrOTPAlreadyVerified.Error()
		}
		if lockedUser.OtpSecret == nil {
			return auth.ErrInvalidOTPCode.Error()
		}

		plainSecret := *lockedUser.OtpSecret
		if dec, err := auth.OtpDecryptString(plainSecret); err == nil {
			plainSecret = dec
		} else {
			plainSecret = ""
		}
		if !totp.Validate(dto.Code, plainSecret) {
			return auth.ErrInvalidOTPCode.Error()
		}

		lockedUser.OtpVerified = true
		lockedUser.OtpBackupCodes = storedCodes
		user.OtpVerified = true
		user.OtpBackupCodes = storedCodes
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "OtpVerified", "OtpBackupCodes")
	})
	if err != nil {
		switch err.Error() {
		case auth.ErrOTPIsNotSet.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FAFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "not_enabled", Details: map[string]any{"action": "verify_totp"}})
			errors.ReturnWithError(c, auth.ErrOTPIsNotSet)
			return
		case auth.ErrOTPAlreadyVerified.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FAFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "already_verified", Details: map[string]any{"action": "verify_totp"}})
			errors.ReturnWithError(c, auth.ErrOTPAlreadyVerified)
			return
		case auth.ErrInvalidOTPCode.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FAFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "invalid_otp", Details: map[string]any{"action": "verify_totp"}})
			errors.ReturnWithError(c, auth.ErrInvalidOTPCode)
			return
		default:
			c.Error(err)
			panic(err)
		}
	}

	logging.Log2FAEnabled(user.ID, user.Email, c.ClientIP())

	c.JSON(200, gin.H{
		"message": "TOTP verified successfully",
		"codes":   plainCodes,
	})
}

func generateRecoveryCodes(count int) ([]string, pq.StringArray) {
	plainCodes := make([]string, count)
	storedCodes := make(pq.StringArray, count)

	for i := 0; i < count; i++ {
		code, err := util.GenerateRandomString(8)
		if err != nil {
			panic(err)
		}

		storedCode, err := auth.OtpEncryptString(code)
		if err != nil {
			panic(err)
		}

		plainCodes[i] = code
		storedCodes[i] = storedCode
	}

	return plainCodes, storedCodes
}

func disableTotp(c *gin.Context) {
	user, _, authErr := auth.RequireFreshBrowserSession(c)
	if authErr != nil {
		c.Error(authErr.Error())
		errors.ReturnWithError(c, authErr)
		return
	}

	dto := &struct {
		Code string `json:"code" binding:"required"`
	}{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	err := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		if !lockedUser.OtpActive {
			return auth.ErrOTPIsNotSet.Error()
		}
		if !lockedUser.OtpVerified {
			return auth.ErrOTPIsNotVerified.Error()
		}
		if err := auth.CheckOtpRateLimit(c.Request.Context(), lockedUser.ID.String()); err != nil {
			return err.Error()
		}

		plainSecret := ""
		if lockedUser.OtpSecret != nil {
			if dec, err := auth.OtpDecryptString(*lockedUser.OtpSecret); err == nil {
				plainSecret = dec
			}
		}

		if !totp.Validate(dto.Code, plainSecret) && !auth.ConsumeBackupCodeFromUser(lockedUser, dto.Code) {
			return auth.ErrInvalidOTPCode.Error()
		}

		lockedUser.OtpActive = false
		lockedUser.OtpVerified = false
		lockedUser.OtpSecret = nil
		lockedUser.OtpBackupCodes = pq.StringArray{}
		user.OtpActive = false
		user.OtpVerified = false
		user.OtpSecret = nil
		user.OtpBackupCodes = pq.StringArray{}
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "OtpActive", "OtpVerified", "OtpSecret", "OtpBackupCodes")
	})
	if err != nil {
		switch err.Error() {
		case auth.ErrOTPIsNotSet.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FAFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "not_enabled", Details: map[string]any{"action": "disable_totp"}})
			errors.ReturnWithError(c, auth.ErrOTPIsNotSet)
			return
		case auth.ErrOTPIsNotVerified.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FAFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "not_verified", Details: map[string]any{"action": "disable_totp"}})
			errors.ReturnWithError(c, auth.ErrOTPIsNotVerified)
			return
		case auth.ErrInvalidOTPCode.String():
			auth.IncrementOtpFailedAttempt(c.Request.Context(), user.ID.String())
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FAFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "invalid_otp", Details: map[string]any{"action": "disable_totp"}})
			logging.Log2FAFailed(user.ID, user.Email, c.ClientIP(), "invalid_otp")
			errors.ReturnWithError(c, auth.ErrInvalidOTPCode)
			return
		case auth.ErrUserOtpRateLimited.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FAFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "otp_rate_limited", Details: map[string]any{"action": "disable_totp"}})
			errors.ReturnWithError(c, auth.ErrUserOtpRateLimited)
			return
		default:
			c.Error(err)
			panic(err)
		}
	}
	auth.ResetOtpFailedAttempts(c.Request.Context(), user.ID.String())
	logging.Log2FADisabled(user.ID, user.Email, c.ClientIP())

	c.JSON(200, gin.H{"message": "TOTP disabled successfully"})
}

func requestUrlForVerification(c *gin.Context) {
	user, _, authErr := auth.RequireFreshBrowserSession(c)
	if authErr != nil {
		c.Error(authErr.Error())
		errors.ReturnWithError(c, authErr)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Ruehrstaat-Squadron",
		AccountName: user.Email,
	})
	if err != nil {
		c.Error(err)
		panic(err)
	}

	secret := key.Secret()
	encryptedSecret, err := auth.OtpEncryptString(secret)
	if err != nil {
		c.Error(err)
		panic(err)
	}

	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		if !lockedUser.OtpActive {
			return auth.ErrOTPIsNotSet.Error()
		}
		if lockedUser.OtpVerified {
			return auth.ErrOTPAlreadyVerified.Error()
		}
		lockedUser.OtpSecret = &encryptedSecret
		lockedUser.OtpActive = true
		user.OtpSecret = &encryptedSecret
		user.OtpActive = true
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "OtpSecret", "OtpActive")
	}); err != nil {
		if err.Error() == auth.ErrOTPIsNotSet.String() {
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FAFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "not_enabled", Details: map[string]any{"action": "request_totp_url"}})
			errors.ReturnWithError(c, auth.ErrOTPIsNotSet)
			return
		}
		if err.Error() == auth.ErrOTPAlreadyVerified.String() {
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FAFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "already_verified", Details: map[string]any{"action": "request_totp_url"}})
			errors.ReturnWithError(c, auth.ErrOTPAlreadyVerified)
			return
		}
		c.Error(err)
		panic(err)
	}

	c.JSON(200, gin.H{"url": key.String()})
}

func removeTotp(c *gin.Context) {
	if _, _, authErr := auth.RequireFreshAdminSession(c); authErr != nil {
		errors.ReturnWithError(c, authErr)
		return
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		errors.ReturnWithError(c, auth.ErrInvalidUUID)
		return
	}

	var userEmail string
	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, userID, func(tx *gorm.DB, lockedUser *entities.User) error {
		userEmail = lockedUser.Email
		if !lockedUser.OtpActive {
			return auth.ErrOTPIsNotSet.Error()
		}
		lockedUser.OtpActive = false
		lockedUser.OtpVerified = false
		lockedUser.OtpSecret = nil
		lockedUser.OtpBackupCodes = nil
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "OtpActive", "OtpVerified", "OtpSecret", "OtpBackupCodes")
	}); err != nil {
		if err == gorm.ErrRecordNotFound {
			errors.ReturnWithError(c, auth.ErrUserNotFound)
			return
		}
		if err.Error() == auth.ErrOTPIsNotSet.String() {
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.Event2FAFailed, UserID: &userID, Email: userEmail, IPAddress: c.ClientIP(), Success: false, ErrorReason: "not_enabled", Details: map[string]any{"action": "admin_remove_totp"}})
			errors.ReturnWithError(c, auth.ErrOTPIsNotSet)
			return
		}
		c.Error(err)
		panic(err)
	}
	logging.Log2FADisabled(userID, userEmail, c.ClientIP())

	c.JSON(200, gin.H{"message": "TOTP removed successfully"})
}
