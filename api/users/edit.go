package users

import (
	"errors"
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func editUser(c *gin.Context) {
	current, authorized := auth.AutoAuthorize(c)
	if !authorized {
		return
	}
	if current == nil {
		c.Error(auth.ErrInvalidToken)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}
	user, err := findUser(current, c.Param("id"))
	if err == auth.ErrInvalidUUID {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Invalid user id"})
		return
	}
	if user != nil && user.ID != current.ID && !current.IsAdmin {
		c.Error(errors.New("user not owned by requester"))
		c.JSON(403, gin.H{"error": "Forbidden"})
		return
	}
	if err == auth.ErrUserNotFound {
		c.Error(err)
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	userDTO := editUserBody{}
	if err := c.ShouldBindJSON(&userDTO); err != nil {
		c.Error(err)
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	//check if email is already taken
	if userDTO.Email != "" && userDTO.Email != user.Email {
		var count int64
		if err := db.DB.Model(&user).Where("email = ?", userDTO.Email).Count(&count).Error; err != nil {
			c.Error(err)
			c.Error(errors.New("failed to get user from db"))
			c.JSON(500, gin.H{"error": "Internal server error"})
			return
		}
		if count > 0 {
			c.Error(errors.New("email is already taken"))
			c.JSON(409, gin.H{"error": "Email is already taken"})
			return
		}
	}

	// check if IsAdmin, IsBanned or Balance is changed, if yes check if user is admin
	if !current.IsAdmin && (userDTO.IsAdmin != nil || userDTO.IsBanned != nil) {
		c.Error(errors.New("user not owned by requester"))
		c.JSON(403, gin.H{"error": "Forbidden"})
		return
	}

	//create gorm transaction
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		//update user
		if err := tx.Model(&user).Updates(userDTO).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		c.Error(err)
		c.Error(errors.New("failed to update user"))
		c.JSON(500, gin.H{"error": "Internal server error"})
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
		c.Error(err)
		c.JSON(400, gin.H{"error": "Invalid user id"})
		return
	}
	if user != nil && user.ID != current.ID && !current.IsAdmin {
		c.Error(errors.New("user not owned by requester"))
		c.JSON(403, gin.H{"error": "Forbidden"})
		return
	}
	if err == auth.ErrUserNotFound {
		c.Error(err)
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	token := c.Query("ect")
	if token == "" {
		c.Error(errors.New("no email change token provided"))
		c.JSON(400, gin.H{"error": "No email change token provided"})
		return
	}

	if err := auth.ChangeEmail(user, token); err != nil {
		if err == auth.ErrInvalidEmailChangeToken {
			c.Error(err)
			c.JSON(400, gin.H{"error": "Invalid email change token"})
			return
		}

		if err == auth.ErrEmailChangeNotRequested {
			c.Error(err)
			c.JSON(400, gin.H{"error": "Email change not requested"})
			return
		}

		c.Error(err)
		c.JSON(500, gin.H{"error": "Internal server error"})
		panic(err)
	}

	c.JSON(200, gin.H{"message": "Email changed successfully"})
}
