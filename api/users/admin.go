package users

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/serialize"

	"github.com/gin-gonic/gin"
)

func adminGetUsers(c *gin.Context) {
	_, authorized := auth.AutoAuthorizeAdmin(c)
	if !authorized {
		return
	}

	// limit at 50
	var users []entities.User
	if res := db.DB.Limit(50).Find(&users); res.Error != nil {
		c.Error(res.Error)
		errors.ReturnWithError(c, auth.ErrAdminFailedToGetFromDB)
		return
	}

	serialize.JSONArray[entities.User](c, (&serialize.UserSerializer{}).ParseFlags(c), users)
}

func adminCreateUser(c *gin.Context) {
	_, authorized := auth.AutoAuthorizeAdmin(c)
	if !authorized {
		return
	}

	var body adminCreateUserBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	if body.IsAdmin == nil {
		isAdmin := false
		body.IsAdmin = &isAdmin
	}

	err := auth.Register(body.Email, body.Password, body.Nickname, body.CmdrName, *body.IsAdmin)
	if err == auth.ErrInvalidEmail {
		errors.ReturnWithError(c, err)
		return
	} else if err == auth.ErrEmailTaken {
		errors.ReturnWithError(c, err)
		return
	} else if err != nil {
		c.Error(err.Error())
		errors.ReturnWithError(c, auth.ErrAdminFailedToRegisterUser)
		return
	}

	user := &entities.User{}
	if res := db.DB.Where("email = ?", body.Email).First(user); res.Error != nil {
		c.Error(res.Error)
		errors.ReturnWithError(c, auth.ErrAdminFailedToGetFromDB)
		return
	}

	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		errors.ReturnWithError(c, auth.ErrAdminFailedToSaveToDB)
		return
	}

	serialize.JSON[entities.User](c, (&serialize.UserSerializer{}).ParseFlags(c), *user)
}
