package auth

import (
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"

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
		errors.ReturnWithError(c, ErrUnauthorized)
		return nil, false
	}

	if user.IsBanned {
		errors.ReturnWithError(c, ErrForbidden)
		return nil, false
	}

	return user, true
}

func AutoAuthorizeAdmin(c *gin.Context) (*entities.User, bool) {
	user := Extract(c)
	if user == nil {
		errors.ReturnWithError(c, ErrUnauthorized)
		return nil, false
	}

	if user.IsBanned {
		errors.ReturnWithError(c, ErrForbidden)
		return nil, false
	}

	if !user.IsAdmin {
		errors.ReturnWithError(c, ErrForbidden)
		return nil, false
	}

	return user, true
}
