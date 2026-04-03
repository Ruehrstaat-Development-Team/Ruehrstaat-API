package users

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/mailer"
	"ruehrstaat-backend/services/user_service"

	"ruehrstaat-backend/services/locale"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func activateUser(c *gin.Context) {
	userIdStr := c.Param("id")
	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		errors.ReturnWithError(c, dtoerr.InvalidId)
		return
	}

	dto := activateUserBody{}
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}
	activationToken := auth.ResolveActivationTokenReference(dto.Activation)

	if err := auth.ActivateAccount(c, userId, activationToken); err != nil {
		if err == auth.ErrUserNotFound {
			c.Error(err.Error())
			errors.ReturnWithError(c, auth.ErrForbidden)
			return
		}

		if err == auth.ErrInvalidActivationToken {
			errors.ReturnWithError(c, err)
			return
		}

		if err == auth.ErrUserAlreadyActivated {
			errors.ReturnWithError(c, err)
			return
		}

		c.Error(err.Error())
		panic(err)
	}

	auth.DeleteActivationTokenReference(dto.Activation)

	c.JSON(200, gin.H{"message": "User activated successfully"})
}

func resendUserActivation(c *gin.Context) {
	activateState := c.Query("state")
	if activateState == "" {
		errors.ReturnWithError(c, auth.ErrNoActivationState)
		return
	}

	var userId *uuid.UUID
	if ok := cache.GetState("resend_activate", activateState, &userId); !ok {
		errors.ReturnWithError(c, auth.ErrInvalidActivationState)
		return
	}

	user := &entities.User{}
	if res := db.DB.Where("id = ?", userId).First(user); res.Error != nil {
		if res.Error == gorm.ErrRecordNotFound {
			c.Error(res.Error)
			errors.ReturnWithError(c, auth.ErrForbidden)
			return
		}

		c.Error(res.Error)
		panic(res.Error)
	}

	if err := auth.GenerateActivationToken(c, user); err != nil {
		c.Error(err.Error())
		panic(err)
	}

	cache.DeleteState("resend_activate", activateState)

	c.JSON(200, gin.H{"message": "Activation token sent successfully"})
}

func requestPasswordReset(c *gin.Context) {
	dto := requestPasswordResetBody{}
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	if err := auth.CheckAndIncrementPasswordResetRequestRateLimit(c.Request.Context(), dto.Email, c.ClientIP()); err != nil {
		c.Error(err.Error())
		c.JSON(200, gin.H{"message": "Reset token sent successfully"})
		return
	}

	user := &entities.User{}
	if err := auth.FindUniqueUserByEmail(c.Request.Context(), dto.Email, user); err != nil {
		if err == auth.ErrUserNotFound || err == auth.ErrEmailAmbiguous {
			c.Error(err.Error())
			c.JSON(200, gin.H{"message": "Reset token sent successfully"})
			return
		}

		c.Error(err.Error())
		panic(err)
	}

	if err := auth.GenerateResetPasswordToken(c, user); err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.JSON(200, gin.H{"message": "Reset token sent successfully"})
}

func resetPassword(c *gin.Context) {
	userIDStr := c.Param("id")
	if userIDStr == "" {
		errors.ReturnWithError(c, dtoerr.InvalidId)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		errors.ReturnWithError(c, dtoerr.InvalidId)
		return
	}

	dto := resetPasswordBody{}
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}
	token := auth.ResolvePasswordResetTokenReference(dto.ResetToken)

	if err := auth.ResetPassword(c, userID, token, dto.Password, dto.Otp); err != nil {
		if err == auth.ErrInvalidResetToken {
			errors.ReturnWithError(c, err)
			return
		}

		if err == auth.ErrUserNotFound {
			c.Error(err.Error())
			errors.ReturnWithError(c, auth.ErrForbidden)
			return
		}

		if err == auth.ErrUserOtpWrong {
			c.Error(err.Error())
			errors.ReturnWithError(c, auth.ErrUserOtpWrong)
			return
		}

		if err == auth.ErrPasswordTooWeak || err == auth.ErrUserOtpMissing || err == auth.ErrUserOtpRateLimited || err == auth.ErrResetNotRequested {
			errors.ReturnWithError(c, err)
			return
		}

		c.Error(err.Error())
		panic(err)
	}

	auth.DeletePasswordResetTokenReference(dto.ResetToken)
	c.JSON(200, gin.H{"message": "Password reset successfully"})
}

func changePassword(c *gin.Context) {
	user, authErr := auth.RequireSessionBoundAuth(c)
	if authErr != nil {
		errors.ReturnWithError(c, authErr)
		return
	}

	dto := &struct {
		OldPassword string  `json:"oldPassword"`
		NewPassword string  `json:"newPassword"`
		Otp         *string `json:"otp"`
	}{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	if err := auth.ChangePassword(c, user, dto.OldPassword, dto.NewPassword, dto.Otp); err != nil {
		if err == auth.ErrInvalidCredentials {
			errors.ReturnWithError(c, err)
			return
		}

		if err == auth.ErrUserOtpWrong || err == auth.ErrUserOtpMissing || err == auth.ErrUserOtpRateLimited || err == auth.ErrPasswordTooWeak {
			errors.ReturnWithError(c, err)
			return
		}

		c.Error(err.Error())
		panic(err)
	}

	c.JSON(200, gin.H{"message": "Password changed successfully"})
}

func requestEmailChange(c *gin.Context) {
	user, authErr := auth.RequireSessionBoundAuth(c)
	if authErr != nil {
		errors.ReturnWithError(c, authErr)
		return
	}

	emailChangeDto := changeEmailBody{}
	if err := c.ShouldBindJSON(&emailChangeDto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	if isNoopEmailChange(user.Email, emailChangeDto.NewEmail) {
		errors.ReturnWithError(c, auth.ErrEmailDidNotChange)
		return
	}

	err := auth.InitiateEmailChange(c, user, emailChangeDto.NewEmail, emailChangeDto.Password, emailChangeDto.Otp)
	if err != nil {
		if err == auth.ErrInvalidEmail {
			errors.ReturnWithError(c, err)
			return
		}
		if err == auth.ErrInvalidCredentials {
			errors.ReturnWithError(c, err)
			return
		}
		if err == auth.ErrUserOtpMissing || err == auth.ErrUserOtpRateLimited {
			errors.ReturnWithError(c, err)
			return
		}
		if err == auth.ErrUserOtpWrong {
			errors.ReturnWithError(c, err)
			return
		}
		if err == auth.ErrEmailTaken {
			errors.ReturnWithError(c, err)
			return
		}

		if err == mailer.ErrFailedToSendEmail {
			errors.ReturnWithError(c, err)
			return
		}
		c.Error(err.Error())
		panic(err)
	}

	c.JSON(200, gin.H{"message": "Email change token sent successfully"})
}

func isNoopEmailChange(currentEmail string, requestedEmail string) bool {
	return auth.NormalizeEmail(currentEmail) == auth.NormalizeEmail(requestedEmail)
}

func setLocale(c *gin.Context) {
	user, authErr := auth.RequireSessionBoundAuth(c)
	if authErr != nil {
		errors.ReturnWithError(c, authErr)
		return
	}

	// get locale query param
	localeStr := c.Query("locale")
	if localeStr == "" {
		errors.ReturnWithError(c, auth.ErrInvalidLocale)
		return
	}

	// check if locale is valid
	if !locale.DoesLocaleExist(localeStr) {
		errors.ReturnWithError(c, auth.ErrInvalidLocale)
		return
	}

	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		lockedUser.Locale = localeStr
		user.Locale = localeStr
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "Locale")
	}); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, auth.ErrServer)
		return
	}

	c.JSON(200, gin.H{"message": "Locale set successfully"})
}
