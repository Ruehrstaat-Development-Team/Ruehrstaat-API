package users

import (
	"errors"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/serialize"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func findUser(current *entities.User, userIdStr string) (*entities.User, error) {
	user := &entities.User{}

	if userIdStr != "@me" {
		userId, err := uuid.Parse(userIdStr)
		if err != nil {
			return nil, auth.ErrInvalidUUID
		}

		if res := db.DB.Where("id = ?", userId).First(user); res.Error != nil {
			return nil, auth.ErrUserNotFound
		}
	} else {
		user = current
	}
	return user, nil
}

func getUser(c *gin.Context) {
	current := auth.Extract(c)
	if current == nil {
		c.Error(auth.ErrInvalidToken)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}
	user, err := findUser(current, c.Param("id"))
	if user != nil && user.ID != current.ID && !current.IsAdmin {
		c.Error(errors.New("user not owned by requester"))
		c.JSON(403, gin.H{"error": "Forbidden"})
		return
	}
	if err == auth.ErrInvalidUUID {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Invalid user id"})
		return
	} else if err == auth.ErrUserNotFound {
		c.Error(err)
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	serialize.JSON[entities.User](c, (&serialize.UserSerializer{}).ParseFlags(c), *user)
}
