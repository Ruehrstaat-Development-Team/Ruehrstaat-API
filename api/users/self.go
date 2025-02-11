package users

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/mailer"

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

	activationToken := c.Query("activation")
	if activationToken == "" {
		errors.ReturnWithError(c, auth.ErrInvalidActivationToken)
		return
	}

	if err := auth.ActivateAccount(userId, activationToken); err != nil {
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

	c.JSON(200, gin.H{"message": "User activated successfully"})
}

func resendUserActivation(c *gin.Context) {
	activateState := c.Query("state")
	if activateState == "" {
		errors.ReturnWithError(c, auth.ErrNoActivationState)
		return
	}

	var userId *uuid.UUID
	if ok := cache.EndState("resend_activate", activateState, &userId); !ok {
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

	if err := auth.GenerateActivationToken(user); err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.JSON(200, gin.H{"message": "Activation token sent successfully"})
}

func requestPasswordReset(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		errors.ReturnWithError(c, auth.ErrInvalidEmail)
		return
	}

	user := &entities.User{}
	if res := db.DB.Where("email = ?", email).First(user); res.Error != nil {
		if res.Error == gorm.ErrRecordNotFound {
			c.Error(res.Error)
			c.Error(auth.ErrUserNotFound.Error())
			errors.ReturnWithError(c, auth.ErrForbidden)
			return
		}

		c.Error(res.Error)
		panic(res.Error)
	}

	if err := auth.GenerateResetPasswordToken(user); err != nil {
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

	token := c.Query("ret")
	if token == "" {
		errors.ReturnWithError(c, auth.ErrInvalidResetToken)
		return
	}

	dto := &struct {
		Password string  `json:"password"`
		Otp      *string `json:"otp"`
	}{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	if err := auth.ResetPassword(userID, token, dto.Password, dto.Otp); err != nil {
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

		c.Error(err.Error())
		panic(err)
	}
}

func changePassword(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken.Error())
		errors.ReturnWithError(c, auth.ErrUnauthorized)
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

	if err := auth.ChangePassword(user, dto.OldPassword, dto.NewPassword, dto.Otp); err != nil {
		if err == auth.ErrInvalidCredentials {
			errors.ReturnWithError(c, err)
			return
		}

		if err == auth.ErrUserOtpWrong {
			errors.ReturnWithError(c, err)
			return
		}

		c.Error(err.Error())
		panic(err)
	}

	c.JSON(200, gin.H{"message": "Password changed successfully"})
}

func requestEmailChange(c *gin.Context) {
	user, authorized := auth.AutoAuthorize(c)
	if !authorized {
		return
	}

	emailChangeDto := changeEmailBody{}
	if err := c.ShouldBindJSON(&emailChangeDto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	if user.Email == emailChangeDto.NewEmail {
		errors.ReturnWithError(c, auth.ErrEmailDidNotChange)
		return
	}

	err := auth.InitiateEmailChange(user, emailChangeDto.NewEmail, emailChangeDto.Password, emailChangeDto.Otp)
	if err != nil {
		if err == auth.ErrInvalidEmail {
			errors.ReturnWithError(c, err)
			return
		}
		if err == auth.ErrInvalidCredentials {
			errors.ReturnWithError(c, err)
			return
		}
		if err == auth.ErrUserOtpMissing {
			errors.ReturnWithError(c, err)
			return
		}
		if err == auth.ErrUserOtpWrong {
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

	// save user
	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		errors.ReturnWithError(c, auth.ErrServer)
		panic(res.Error)
	}
	c.JSON(200, gin.H{"message": "Email change token sent successfully"})
}

func setLocale(c *gin.Context) {
	user, authorized := auth.AutoAuthorize(c)
	if !authorized {
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

	user.Locale = localeStr

	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		errors.ReturnWithError(c, auth.ErrServer)
		return
	}

	c.JSON(200, gin.H{"message": "Locale set successfully"})
}
