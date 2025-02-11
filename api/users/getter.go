package users

import (
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/serialize"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func findUser(current *entities.User, userIdStr string) (*entities.User, *errors.RstError) {
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
		errors.ReturnWithError(c, auth.ErrUnauthorized)
		return
	}
	user, err := findUser(current, c.Param("id"))
	if user != nil && user.ID != current.ID && !current.IsAdmin {
		errors.ReturnWithError(c, auth.ErrForbidden)
		return
	}
	if err == auth.ErrInvalidUUID {
		errors.ReturnWithError(c, err)
		return
	} else if err == auth.ErrUserNotFound {
		errors.ReturnWithError(c, err)
		return
	}

	serialize.JSON[entities.User](c, (&serialize.UserSerializer{}).ParseFlags(c), *user)
}
