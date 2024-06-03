package users

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/util"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	"github.com/pquerna/otp/totp"
)

func beginTotp(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		errors.ReturnWithError(c, auth.ErrUnauthorized)
		return
	}

	if user.OtpActive {
		errors.ReturnWithError(c, auth.ErrOTPAlreadySet)
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
	user.OtpSecret = &secret
	user.OtpActive = true

	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		panic(res.Error)
	}

	c.JSON(200, gin.H{"url": key.String()})
}

func verifyTotp(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		errors.ReturnWithError(c, auth.ErrUnauthorized)
		return
	}

	if !user.OtpActive {
		errors.ReturnWithError(c, auth.ErrOTPIsNotSet)
		return
	}

	if user.OtpVerified {
		errors.ReturnWithError(c, auth.ErrOTPAlreadyVerified)
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

	if !totp.Validate(dto.Code, *user.OtpSecret) {
		errors.ReturnWithError(c, auth.ErrInvalidOTPCode)
		return
	}

	user.OtpVerified = true
	user.OtpBackupCodes = generateRecoveryCodes(10)

	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		panic(res.Error)
	}

	c.JSON(200, gin.H{
		"message": "TOTP verified successfully",
		"codes":   user.OtpBackupCodes,
	})
}

func generateRecoveryCodes(count int) []string {
	codes := make([]string, count)

	for i := 0; i < count; i++ {
		code, err := util.GenerateRandomString(8)
		if err != nil {
			panic(err)
		}

		codes[i] = code
	}

	return codes
}

func disableTotp(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		errors.ReturnWithError(c, auth.ErrUnauthorized)
		return
	}

	if !user.OtpActive {
		errors.ReturnWithError(c, auth.ErrOTPIsNotSet)
		return
	}

	if !user.OtpVerified {
		errors.ReturnWithError(c, auth.ErrOTPIsNotVerified)
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

	if !totp.Validate(dto.Code, *user.OtpSecret) {
		if err := auth.TryBackupCodes(user, &dto.Code); err != nil {
			c.Error(err)
			errors.ReturnWithError(c, auth.ErrInvalidOTPCode)
			return
		}
	}

	user.OtpActive = false
	user.OtpVerified = false
	user.OtpSecret = nil
	user.OtpBackupCodes = pq.StringArray{}

	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		panic(res.Error)
	}

	c.JSON(200, gin.H{"message": "TOTP disabled successfully"})
}

func requestUrlForVerification(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		errors.ReturnWithError(c, auth.ErrUnauthorized)
		return
	}

	if !user.OtpActive {
		errors.ReturnWithError(c, auth.ErrOTPIsNotSet)
		return
	}

	if user.OtpVerified {
		errors.ReturnWithError(c, auth.ErrOTPAlreadyVerified)
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
	user.OtpSecret = &secret
	user.OtpActive = true

	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		panic(res.Error)
	}

	c.JSON(200, gin.H{"url": key.String()})
}

func removeTotp(c *gin.Context) {
	if _, ok := auth.AutoAuthorizeAdmin(c); !ok {
		c.Error(auth.ErrInvalidToken)
		errors.ReturnWithError(c, auth.ErrUnauthorized)
		return
	}

	user := &entities.User{}
	if res := db.DB.First(user, c.Param("id")); res.Error != nil {
		c.Error(res.Error)
		errors.ReturnWithError(c, auth.ErrUserNotFound)
		return
	}

	if !user.OtpActive {
		errors.ReturnWithError(c, auth.ErrOTPIsNotSet)
		return
	}

	user.OtpActive = false
	user.OtpVerified = false
	user.OtpSecret = nil
	user.OtpBackupCodes = nil

	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		panic(res.Error)
	}

	c.JSON(200, gin.H{"message": "TOTP removed successfully"})
}
