package users

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/errors"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func editUser(c *gin.Context) {
	current, authorized := auth.AutoAuthorize(c)
	if !authorized {
		return
	}
	if current == nil {
		errors.ReturnWithError(c, auth.ErrInvalidToken)
		return
	}
	user, err := findUser(current, c.Param("id"))
	if err == auth.ErrInvalidUUID {
		errors.ReturnWithError(c, err)
		return
	}
	if user != nil && user.ID != current.ID && !current.IsAdmin {
		errors.ReturnWithError(c, auth.ErrForbidden)
		return
	}
	if err == auth.ErrUserNotFound {
		errors.ReturnWithError(c, auth.ErrUserNotFound)
		return
	}

	userDTO := editUserBody{}
	if err := c.ShouldBindJSON(&userDTO); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	//check if email is already taken
	if userDTO.Email != "" && userDTO.Email != user.Email {
		var count int64
		if err := db.DB.Model(&user).Where("email = ?", userDTO.Email).Count(&count).Error; err != nil {
			c.Error(err)
			errors.ReturnWithError(c, auth.ErrAdminFailedToGetFromDB)
			return
		}
		if count > 0 {
			errors.ReturnWithError(c, auth.ErrEmailTaken)
			return
		}
	}

	// check if IsAdmin, IsBanned or Balance is changed, if yes check if user is admin
	if !current.IsAdmin && (userDTO.IsAdmin != nil || userDTO.IsBanned != nil) {
		c.JSON(403, gin.H{"error": "Forbidden"})
		return
	}

	//create gorm transaction
	err2 := db.DB.Transaction(func(tx *gorm.DB) error {
		//update user
		if err := tx.Model(&user).Updates(userDTO).Error; err != nil {
			return err
		}

		return nil
	})

	if err2 != nil {
		c.Error(err.Error())
		errors.ReturnWithError(c, auth.ErrAdminFailedToSaveToDB)
		return
	}

	c.JSON(200, gin.H{"message": "User updated successfully"})
}

func changeEmail(c *gin.Context) {
	current, authorized := auth.AutoAuthorize(c)
	if !authorized {
		return
	}

	user, err := findUser(current, c.Param("id"))
	if err == auth.ErrInvalidUUID {
		errors.ReturnWithError(c, err)
		return
	}
	if user != nil && user.ID != current.ID && !current.IsAdmin {
		errors.ReturnWithError(c, auth.ErrForbidden)
		return
	}
	if err == auth.ErrUserNotFound {
		errors.ReturnWithError(c, auth.ErrUserNotFound)
		return
	}

	token := c.Query("ect")
	if token == "" {
		errors.ReturnWithError(c, auth.ErrInvalidEmailChangeToken)
		return
	}

	if err := auth.ChangeEmail(user, token); err != nil {
		if err == auth.ErrInvalidEmailChangeToken {
			errors.ReturnWithError(c, err)
			return
		}

		if err == auth.ErrEmailChangeNotRequested {
			errors.ReturnWithError(c, err)
			return
		}

		c.Error(err.Error())
		errors.ReturnWithError(c, auth.ErrServer)
		panic(err)
	}

	c.JSON(200, gin.H{"message": "Email changed successfully"})
}
