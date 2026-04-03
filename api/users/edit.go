package users

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/services/user_service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func editUser(c *gin.Context) {
	current, authErr := auth.RequireSessionBoundAuth(c)
	if authErr != nil {
		errors.ReturnWithError(c, authErr)
		return
	}

	targetUserID := current.ID
	if userID := c.Param("id"); userID != "@me" {
		parsedUserID, err := uuid.Parse(userID)
		if err != nil {
			errors.ReturnWithError(c, auth.ErrInvalidUUID)
			return
		}
		targetUserID = parsedUserID
	}

	userDTO := editUserBody{}
	if err := c.ShouldBindJSON(&userDTO); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	if userDTO.Email != "" && !current.IsAdmin {
		errors.ReturnWithError(c, auth.ErrForbidden)
		return
	}

	if userDTO.Email != "" {
		userDTO.Email = auth.NormalizeEmail(userDTO.Email)
		if err := auth.ValidateUserEmailAddress(userDTO.Email); err != nil {
			errors.ReturnWithError(c, err)
			return
		}
	}

	// check if IsAdmin, IsBanned or Balance is changed, if yes check if user is admin
	if !current.IsAdmin && (userDTO.IsAdmin != nil || userDTO.IsBanned != nil) {
		errors.ReturnWithError(c, auth.ErrForbidden)
		return
	}

	requiresFreshAdminSession := current.IsAdmin && (targetUserID != current.ID || userDTO.Email != "" || userDTO.IsAdmin != nil || userDTO.IsBanned != nil)
	if requiresFreshAdminSession {
		freshCurrent, _, freshErr := auth.RequireFreshAdminSession(c)
		if freshErr != nil {
			errors.ReturnWithError(c, freshErr)
			return
		}
		current = freshCurrent
	}

	revokeAuth := false
	err2 := db.DB.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		lockedUser, err := user_service.GetUserForUpdate(c.Request.Context(), tx, targetUserID)
		if err != nil {
			return err
		}
		if lockedUser.ID != current.ID && !current.IsAdmin {
			return auth.ErrForbidden.Error()
		}

		columns := []string{}
		if userDTO.Email != "" && userDTO.Email != lockedUser.Email {
			if err := auth.AcquireNormalizedEmailLock(tx, userDTO.Email); err != nil {
				return err
			}

			var count int64
			if err := tx.Model(lockedUser).Where(auth.NormalizedEmailWhereClauseExcludingID(), userDTO.Email, lockedUser.ID).Count(&count).Error; err != nil {
				return err
			}
			if count > 0 {
				return auth.ErrEmailTaken.Error()
			}
			lockedUser.Email = userDTO.Email
			columns = append(columns, "Email")
			if lockedUser.NewEmail != nil {
				lockedUser.NewEmail = nil
				columns = append(columns, "NewEmail")
			}
			if lockedUser.EmailChangeToken != nil {
				lockedUser.EmailChangeToken = nil
				columns = append(columns, "EmailChangeToken")
			}
		}
		if userDTO.Nickname != "" {
			lockedUser.Nickname = userDTO.Nickname
			columns = append(columns, "Nickname")
		}
		if userDTO.CmdrName != "" {
			lockedUser.CmdrName = userDTO.CmdrName
			columns = append(columns, "CmdrName")
		}
		if userDTO.IsAdmin != nil {
			lockedUser.IsAdmin = *userDTO.IsAdmin
			columns = append(columns, "IsAdmin")
		}
		if userDTO.IsBanned != nil {
			if *userDTO.IsBanned && !lockedUser.IsBanned {
				revokeAuth = true
			}
			lockedUser.IsBanned = *userDTO.IsBanned
			columns = append(columns, "IsBanned")
		}

		if len(columns) == 0 {
			return nil
		}

		if err := user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, columns...); err != nil {
			return err
		}
		if !revokeAuth {
			return nil
		}

		if err := auth.RevokeAllSessionsForUserTx(c.Request.Context(), tx, lockedUser.ID); err != nil {
			return err
		}
		return auth.RevokeApiTokensForUser(c.Request.Context(), tx, lockedUser.ID)
	})

	if err2 != nil {
		if err2 == gorm.ErrRecordNotFound {
			errors.ReturnWithError(c, auth.ErrUserNotFound)
			return
		}
		if err2.Error() == auth.ErrForbidden.String() {
			errors.ReturnWithError(c, auth.ErrForbidden)
			return
		}
		if err2.Error() == auth.ErrEmailTaken.String() {
			errors.ReturnWithError(c, auth.ErrEmailTaken)
			return
		}
		c.Error(err2)
		errors.ReturnWithError(c, auth.ErrAdminFailedToSaveToDB)
		return
	}

	c.JSON(200, gin.H{"message": "User updated successfully"})
}

func changeEmail(c *gin.Context) {
	userID, parseErr := uuid.Parse(c.Param("id"))
	if parseErr != nil {
		errors.ReturnWithError(c, auth.ErrInvalidUUID)
		return
	}

	dto := confirmEmailChangeBody{}
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	user := &entities.User{}
	if res := db.DB.WithContext(c.Request.Context()).Where("id = ?", userID).First(user); res.Error != nil {
		if res.Error == gorm.ErrRecordNotFound {
			c.Error(res.Error)
			errors.ReturnWithError(c, auth.ErrForbidden)
			return
		}

		c.Error(res.Error)
		panic(res.Error)
	}

	token := auth.ResolveEmailChangeTokenReference(dto.EmailChangeToken)

	if err := auth.ChangeEmail(c, user, token); err != nil {
		if err == auth.ErrEmailTaken {
			errors.ReturnWithError(c, err)
			return
		}
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
		return
	}

	auth.DeleteEmailChangeTokenReference(dto.EmailChangeToken)

	c.JSON(200, gin.H{"message": "Email changed successfully"})
}
