package auth

import (
	"ruehrstaat-backend/db/entities"

	"github.com/gin-gonic/gin"
)

func Authorize(c *gin.Context) (*entities.User, bool) {
	user := Extract(c)
	if user == nil {
		return nil, false
	}

	return user, user.IsAdmin
}

func AutoAuthorize(c *gin.Context) (*entities.User, bool) {
	user := Extract(c)
	if user == nil {
		c.Error(ErrUnauthorized)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil, false
	}

	if user.IsBanned {
		c.Error(ErrForbidden)
		c.JSON(403, gin.H{"error": "Forbidden"})
		return nil, false
	}

	return user, true
}

func AutoAuthorizeAdmin(c *gin.Context) (*entities.User, bool) {
	user := Extract(c)
	if user == nil {
		c.Error(ErrUnauthorized)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return nil, false
	}

	if user.IsBanned {
		c.Error(ErrForbidden)
		c.JSON(403, gin.H{"error": "Forbidden"})
		return nil, false
	}

	if !user.IsAdmin {
		c.Error(ErrForbidden)
		c.JSON(403, gin.H{"error": "Forbidden"})
		return nil, false
	}

	return user, true
}
