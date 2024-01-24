package users

import (
	"errors"
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
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
		c.Error(dtoerr.InvalidId)
		c.JSON(400, gin.H{"error": "Invalid user id"})
		return
	}

	activationToken := c.Query("activation")
	if activationToken == "" {
		c.Error(errors.New("no activation token provided"))
		c.JSON(400, gin.H{"error": "No activation token provided"})
		return
	}

	if err := auth.ActivateAccount(userId, activationToken); err != nil {
		if err == auth.ErrUserNotFound {
			c.Error(err)
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}

		if err == auth.ErrInvalidActivationToken {
			c.Error(err)
			c.JSON(400, gin.H{"error": "Invalid activation token"})
			return
		}

		if err == auth.ErrUserAlreadyActivated {
			c.Error(err)
			c.JSON(409, gin.H{"error": "User is already activated"})
			return
		}

		c.Error(err)
		panic(err)
	}

	c.JSON(200, gin.H{"message": "User activated successfully"})
}

func resendUserActivation(c *gin.Context) {
	activateState := c.Query("state")
	if activateState == "" {
		c.Error(errors.New("no activation state provided"))
		c.JSON(400, gin.H{"error": "No activation state provided"})
		return
	}

	var userId *uuid.UUID
	if ok := cache.EndState("resend_activate", activateState, &userId); !ok {
		c.Error(errors.New("invalid activation state"))
		c.JSON(400, gin.H{"error": "Invalid activation state"})
		return
	}

	user := &entities.User{}
	if res := db.DB.Where("id = ?", userId).First(user); res.Error != nil {
		if res.Error == gorm.ErrRecordNotFound {
			c.Error(res.Error)
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}

		c.Error(res.Error)
		panic(res.Error)
	}

	if err := auth.GenerateActivationToken(user); err != nil {
		c.Error(err)
		panic(err)
	}

	c.JSON(200, gin.H{"message": "Activation token sent successfully"})
}

func requestPasswordReset(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		c.Error(errors.New("no email provided"))
		c.JSON(400, gin.H{"error": "No email provided"})
		return
	}

	user := &entities.User{}
	if res := db.DB.Where("email = ?", email).First(user); res.Error != nil {
		if res.Error == gorm.ErrRecordNotFound {
			c.Error(res.Error)
			c.Error(auth.ErrUserNotFound)
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}

		c.Error(res.Error)
		panic(res.Error)
	}

	if err := auth.GenerateResetPasswordToken(user); err != nil {
		c.Error(err)
		panic(err)
	}

	c.JSON(200, gin.H{"message": "Reset token sent successfully"})
}

func resetPassword(c *gin.Context) {
	userIDStr := c.Param("id")
	if userIDStr == "" {
		c.Error(dtoerr.NoIdProvided)
		c.JSON(400, gin.H{"error": "No user id provided"})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Error(dtoerr.InvalidId)
		c.JSON(400, gin.H{"error": "Invalid user id"})
		return
	}

	token := c.Query("ret")
	if token == "" {
		c.Error(errors.New("no reset token provided"))
		c.JSON(400, gin.H{"error": "No reset token provided"})
		return
	}

	dto := &struct {
		Password string  `json:"password"`
		Otp      *string `json:"otp"`
	}{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": "Given data is invalid"})
		return
	}

	if err := auth.ResetPassword(userID, token, dto.Password, dto.Otp); err != nil {
		if err == auth.ErrInvalidResetToken {
			c.Error(err)
			c.JSON(400, gin.H{"error": "Invalid reset token"})
			return
		}

		if err == auth.ErrUserNotFound {
			c.Error(err)
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}

		if err == auth.ErrUserOtpWrong {
			c.Error(err)
			c.JSON(400, gin.H{"error": "Invalid OTP"})
			return
		}

		c.Error(err)
		panic(err)
	}
}

func changePassword(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	dto := &struct {
		OldPassword string  `json:"oldPassword"`
		NewPassword string  `json:"newPassword"`
		Otp         *string `json:"otp"`
	}{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": "Given data is invalid"})
		return
	}

	if err := auth.ChangePassword(user, dto.OldPassword, dto.NewPassword, dto.Otp); err != nil {
		if err == auth.ErrInvalidCredentials {
			c.Error(err)
			c.JSON(400, gin.H{"error": "Invalid credentials"})
			return
		}

		if err == auth.ErrUserOtpWrong {
			c.Error(err)
			c.JSON(400, gin.H{"error": "Invalid OTP"})
			return
		}

		c.Error(err)
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
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if user.Email == emailChangeDto.NewEmail {
		c.Error(errors.New("new email is same as current email"))
		c.JSON(400, gin.H{"error": "New email is same as current email"})
		return
	}

	err := auth.InitiateEmailChange(user, emailChangeDto.NewEmail, emailChangeDto.Password, emailChangeDto.Otp)
	if err != nil {
		if err == auth.ErrInvalidEmail {
			c.Error(err)
			c.JSON(400, gin.H{"error": "Invalid email"})
			return
		}
		if err == auth.ErrInvalidCredentials {
			c.Error(err)
			c.JSON(400, gin.H{"error": "Invalid credentials"})
			return
		}
		if err == auth.ErrUserOtpMissing {
			c.Error(err)
			c.JSON(400, gin.H{"error": "OTP is missing"})
			return
		}
		if err == auth.ErrUserOtpWrong {
			c.Error(err)
			c.JSON(400, gin.H{"error": "Invalid OTP"})
			return
		}

		if err == mailer.ErrFailedToSendEmail {
			c.Error(err)
			c.JSON(500, gin.H{"error": "Failed to send email"})
			return
		}
		c.Error(err)
		panic(err)
	}

	// save user
	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		c.JSON(500, gin.H{"error": "Internal server error"})
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
		c.Error(errors.New("no locale provided"))
		c.JSON(400, gin.H{"error": "No locale provided"})
		return
	}

	// check if locale is valid
	if !locale.DoesLocaleExist(localeStr) {
		c.Error(errors.New("invalid locale"))
		c.JSON(400, gin.H{"error": "Invalid locale"})
		return
	}

	user.Locale = localeStr

	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		c.Error(errors.New("failed to save user to db"))
		c.JSON(500, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(200, gin.H{"message": "Locale set successfully"})
}
