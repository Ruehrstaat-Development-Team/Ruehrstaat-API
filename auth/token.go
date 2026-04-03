package auth

import (
	"context"
	"strings"
	"time"

	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/util"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const infraSecretHashPrefix = "sha512:"

var authLog = logging.Logger{Package: "auth"}

type TokenPair struct {
	RefreshToken string    `json:"-"`
	IdenityToken string    `json:"token"`
	ExpiresAt    int64     `json:"expiresAt"` // expiry unix timestamp
	SessionID    uuid.UUID `json:"-"`
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
	if res := db.DB.WithContext(c.Request.Context()).Where("id::text = ? OR name = ?", clientId, clientId).First(infra); res.Error != nil {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	secretValid := false
	secretHash := infraSecretHashPrefix + util.HashToken(clientSecret)

	if strings.HasPrefix(infra.Secret, infraSecretHashPrefix) {
		if infra.Secret == secretHash {
			secretValid = true
		}
	} else {
		if infra.Secret == clientSecret {
			secretValid = true
			infra.Secret = secretHash
			if err := db.DB.WithContext(c.Request.Context()).Save(infra).Error; err != nil {
				authLog.Printf("Failed to migrate infra token secret to hash: %v", err)
			}
		}
	}

	if !secretValid {
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
	if res := db.DB.WithContext(c.Request.Context()).Where("user_id = ? AND prefix = ?", userid, prefix).First(apiToken); res.Error != nil {
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

	user := &entities.User{}
	if res := db.DB.WithContext(c.Request.Context()).Where("id = ?", apiToken.UserID).First(user); res.Error != nil {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}
	if err := CheckUserLoginAllowance(user); err != nil {
		_ = RevokeApiTokensForUser(c.Request.Context(), db.DB, apiToken.UserID)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil
	}

	return apiToken
}

func RevokeApiTokensForUser(ctx context.Context, dbConn *gorm.DB, userID uuid.UUID) error {
	if dbConn == nil {
		dbConn = db.DB
	}

	return dbConn.WithContext(ctx).Model(&entities.ApiToken{}).Where("user_id = ?", userID).Update("is_revoked", true).Error
}

func HashInfraSecret(plaintext string) string {
	return infraSecretHashPrefix + util.HashToken(plaintext)
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

func RegisterAPIToken(user *entities.User) (*entities.ApiToken, string, *errors.RstError) {
	// generate 64 char token
	tokenClear, err := util.GenerateRandomString(64)
	if err != nil {
		return nil, "", errors.NewFromError(err)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(tokenClear), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", errors.NewFromError(err)
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
		return nil, "", errors.NewDBErrorFromError(res.Error)
	}

	return apiToken, tokenClear, nil
}
