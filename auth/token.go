package auth

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"

	"github.com/gin-gonic/gin"
)

type TokenPair struct {
	RefreshToken string `json:"-"`
	IdenityToken string `json:"token"`
	ExpiresIn    int64  `json:"expiresIn"`
}

func AuthenticateInfra(c *gin.Context) *entities.InfraToken {
	clientId := c.GetHeader("X-RST-Client-Id")
	if clientId == "" {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	clientSecret := c.GetHeader("X-RST-Client-Secret")
	if clientSecret == "" {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	infra := &entities.InfraToken{}
	if res := db.DB.Where("id = ? AND secret = ?", clientId, clientSecret).First(infra); res.Error != nil {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	return infra
}

func AuthenticateApiToken(c *gin.Context) *entities.ApiToken {
	userid := c.GetHeader("X-RST-User-Id")
	if userid == "" {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	token := c.GetHeader("X-RST-Token")
	if token == "" {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	apiToken := &entities.ApiToken{}
	if res := db.DB.Where("user_id = ? AND token = ?", userid, token).First(apiToken); res.Error != nil {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	return apiToken
}
