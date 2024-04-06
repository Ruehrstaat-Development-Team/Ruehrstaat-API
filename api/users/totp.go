package users

import (
	"errors"
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/util"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	"github.com/pquerna/otp/totp"
)

func beginTotp(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	if user.OtpActive {
		c.Error(errors.New("TOTP is already active"))
		c.JSON(400, gin.H{"error": "TOTP is already active"})
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
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	if !user.OtpActive {
		c.Error(errors.New("TOTP is not active"))
		c.JSON(400, gin.H{"error": "TOTP is not active"})
		return
	}

	if user.OtpVerified {
		c.Error(errors.New("TOTP is already verified"))
		c.JSON(400, gin.H{"error": "TOTP is already verified"})
		return
	}

	dto := &struct {
		Code string `json:"code" binding:"required"`
	}{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": "Given data is invalid"})
		return
	}

	if !totp.Validate(dto.Code, *user.OtpSecret) {
		c.Error(errors.New("invalid code"))
		c.JSON(403, gin.H{"error": "Invalid code"})
		return
	}

	user.OtpVerified = true
	user.OtpBackupCodes = generateRecoveryCodes(10)

	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		c.Error(errors.New("failed to save user to db"))
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
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	if !user.OtpActive {
		c.Error(errors.New("TOTP is not active"))
		c.JSON(400, gin.H{"error": "TOTP is not active"})
		return
	}

	if !user.OtpVerified {
		c.Error(errors.New("TOTP is not verified"))
		c.JSON(400, gin.H{"error": "TOTP is not verified"})
		return
	}

	dto := &struct {
		Code string `json:"code" binding:"required"`
	}{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": "Given data is invalid"})
		return
	}

	if !totp.Validate(dto.Code, *user.OtpSecret) {
		if err := auth.TryBackupCodes(user, &dto.Code); err != nil {
			c.Error(err)
			c.Error(errors.New("invalid code"))
			c.JSON(403, gin.H{"error": "Invalid code"})
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
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	if !user.OtpActive {
		c.Error(errors.New("TOTP is not active"))
		c.JSON(400, gin.H{"error": "TOTP is not active"})
		return
	}

	if user.OtpVerified {
		c.Error(errors.New("TOTP is already verified"))
		c.JSON(400, gin.H{"error": "TOTP is already verified"})
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
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	user := &entities.User{}
	if res := db.DB.First(user, c.Param("id")); res.Error != nil {
		c.Error(res.Error)
		c.Error(errors.New("user not found"))
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	if !user.OtpActive {
		c.Error(errors.New("TOTP is not active"))
		c.JSON(400, gin.H{"error": "TOTP is not active"})
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
