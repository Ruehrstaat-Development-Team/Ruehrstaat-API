package auth

import (
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"

	"github.com/gin-gonic/gin"
)

func requestQuickLoginToken(c *gin.Context) {
	token, sessionId, err := auth.RequestQuickLoginToken()
	if err != nil {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Could not request quick login token"})
	}

	c.JSON(200, gin.H{"token": token, "sessionId": sessionId})
}

type verifyQuickLoginTokenDTO struct {
	Token string `json:"token"`
}

func verifyQuickLoginToken(c *gin.Context) {
	user, authorized := auth.AutoAuthorize(c)
	if !authorized {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	verifyDTO := verifyQuickLoginTokenDTO{}
	if err := c.ShouldBindJSON(&verifyDTO); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	token := verifyDTO.Token

	err := auth.VerifyQuickLoginToken(token, user)
	if err != nil {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Could not verify quick login token"})
		return
	}

	c.JSON(200, gin.H{"message": "Token verified"})
}

type completeQuickLoginDTO struct {
	Token     string `json:"token"`
	SessionID string `json:"sessionId"`
}

func completeQuickLogin(c *gin.Context) {
	dto := completeQuickLoginDTO{}
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	token := dto.Token
	sessionID := dto.SessionID

	userId, err := auth.CompleteQuickLogin(token, sessionID)
	if err != nil {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Could not complete quick login"})
		return
	}

	var user entities.User
	if res := db.DB.Where("id = ?", userId).First(&user); res.Error != nil {
		c.Error(res.Error)
		c.JSON(500, gin.H{"error": "Could not complete quick login"})
		return
	}

	if err := auth.CheckUserLoginAllowance(&user); err != nil {
		c.JSON(400, gin.H{"error": "Could not complete quick login - user not allowed"})
		return
	}

	jwttoken, err := auth.CreateTokenPairForUser(&user)
	if err != nil {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Could not complete quick login"})
		return
	}

	c.JSON(200, gin.H{"token": jwttoken, "refreshToken": jwttoken.RefreshToken})
}
