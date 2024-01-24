package auth

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"

	"github.com/gin-gonic/gin"
)

func AuthenticateInfra(c *gin.Context) *entities.InfraToken {
	clientId := c.GetHeader("X-MTN-Client-Id")
	if clientId == "" {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	clientSecret := c.GetHeader("X-MTN-Client-Secret")
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
