package users

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
)

func beginFido2Link(c *gin.Context) {
	user, session, err := auth.RequireFreshBrowserSession(c)
	if err != nil {
		c.Error(err.Error())
		errors.ReturnWithError(c, err)
		return
	}

	displayName := c.Query("display_name")
	if displayName == "" {
		displayName = user.Email + " FIDO2 Schlüssel"
	}

	state, options, err := auth.BeginFido2Register(user, session, displayName)
	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.JSON(200, gin.H{"state": state, "options": options})
}

func endFido2Link(c *gin.Context) {
	user, session, err := auth.RequireFreshBrowserSession(c)
	if err != nil {
		c.Error(err.Error())
		errors.ReturnWithError(c, err)
		return
	}

	state := c.Query("state")
	if state == "" {
		errors.ReturnWithError(c, auth.ErrStateIsMissing)
		return
	}

	pcc, perr := protocol.ParseCredentialCreationResponseBody(c.Request.Body)
	if perr != nil {
		c.Error(perr)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	err = auth.FinishFido2Register(c, state, user, session, pcc)
	if err != nil {
		if err == auth.ErrInvalidState || err == auth.ErrDuplicateFidoDisplayName || err == auth.ErrInvalidFido2Ceremony {
			errors.ReturnWithError(c, err)
			return
		}

		c.Error(err.Error())
		panic(err)
	}

	c.JSON(200, gin.H{"success": true})
}

func unlinkFido2(c *gin.Context) {
	user, _, err := auth.RequireFreshBrowserSession(c)
	if err != nil {
		c.Error(err.Error())
		errors.ReturnWithError(c, err)
		return
	}

	name := c.Param("name")
	if name == "" {
		errors.ReturnWithError(c, auth.ErrFidoNameIsMissing)
		return
	}

	err = auth.DeleteFido2Login(c, user, user.ID, name)
	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.JSON(200, gin.H{"success": true})
}

func getFido2Links(c *gin.Context) {
	user, authErr := auth.RequireSessionBoundAuth(c)
	if authErr != nil {
		errors.ReturnWithError(c, authErr)
		return
	}

	logins := []entities.Fido2Login{}
	if res := db.DB.Where("user_id = ?", user.ID).Find(&logins); res.Error != nil {
		c.Error(res.Error)
		panic(res.Error)
	}

	formatted := []string{}
	for _, login := range logins {
		formatted = append(formatted, login.DisplayName)
	}

	c.JSON(200, formatted)
}
