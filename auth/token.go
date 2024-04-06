package auth

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/util"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type TokenPair struct {
	RefreshToken string `json:"-"`
	IdenityToken string `json:"token"`
	ExpiresAt    int64  `json:"expiresAt"` // expiry unix timestamp
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

	// token should be 64 chars long
	if len(token) != 64 {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	// prefix is first 8 chars of token
	prefix := token[:8]

	apiToken := &entities.ApiToken{}
	if res := db.DB.Where("user_id = ? AND prefix = ?", userid, prefix).First(apiToken); res.Error != nil {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	if err := bcrypt.CompareHashAndPassword([]byte(apiToken.Token), []byte(token)); err != nil {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	// check if token is revoked
	if checkTokenExpired(apiToken) {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	return apiToken
}

func checkTokenExpired(token *entities.ApiToken) bool {
	if token.IsRevoked {
		return true
	}
	if token.ExpiresAt.Before(time.Now()) {
		token.IsRevoked = true
	}

	if res := db.DB.Save(token); res.Error != nil {
		return true
	}

	return token.IsRevoked
}

func RegisterAPIToken(user *entities.User) (*entities.ApiToken, string, error) {
	// generate 64 char token
	tokenClear, err := util.GenerateRandomString(64)
	if err != nil {
		return nil, "", err
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(tokenClear), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}

	apiToken := &entities.ApiToken{
		UserID:             user.ID,
		Token:              string(hashed),
		Prefix:             tokenClear[:8],
		ExpiresAt:          time.Now().AddDate(1, 0, 0),
		IsRevoked:          false,
		HasFullWriteAccess: false,
		HasFullReadAccess:  false,
		HasReadAccessTo:    []uuid.UUID{},
		HasWriteAccessTo:   []uuid.UUID{},
	}

	if res := db.DB.Create(apiToken); res.Error != nil {
		return nil, "", res.Error
	}

	return apiToken, tokenClear, nil
}
