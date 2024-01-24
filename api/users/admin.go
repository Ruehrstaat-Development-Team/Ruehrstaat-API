package users

import (
	"errors"
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
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
		c.Error(errors.New("failed to get users from db"))
		c.JSON(500, gin.H{"error": "Internal server error"})
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
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": "Invalid request body"})
		return
	}

	if body.IsAdmin == nil {
		isAdmin := false
		body.IsAdmin = &isAdmin
	}

	err := auth.Register(body.Email, body.Password, body.Nickname, body.CmdrName, *body.IsAdmin)
	if err == auth.ErrInvalidEmail {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Invalid email"})
		return
	} else if err == auth.ErrEmailTaken {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Email already taken"})
		return
	} else if err != nil {
		c.Error(err)
		c.Error(errors.New("failed to register user"))
		c.JSON(500, gin.H{"error": "Internal server error"})
		return
	}

	user := &entities.User{}
	if res := db.DB.Where("email = ?", body.Email).First(user); res.Error != nil {
		c.Error(res.Error)
		c.Error(errors.New("failed to get user from db"))
		c.JSON(500, gin.H{"error": "Internal server error"})
		return
	}

	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		c.Error(errors.New("failed to save user to db"))
		c.JSON(500, gin.H{"error": "Internal server error"})
		return
	}

	serialize.JSON[entities.User](c, (&serialize.UserSerializer{}).ParseFlags(c), *user)
}
