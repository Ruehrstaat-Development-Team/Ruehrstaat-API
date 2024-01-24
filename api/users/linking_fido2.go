package users

import (
	"errors"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
)

func beginFido2Link(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	displayName := c.Query("display_name")
	if displayName == "" {
		displayName = user.Email + " FIDO2 Schlüssel"
	}

	state, options, err := auth.BeginFido2Register(user, displayName)
	if err != nil {
		c.Error(err)
		panic(err)
	}

	c.JSON(200, gin.H{"state": state, "options": options})
}

func endFido2Link(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	state := c.Query("state")
	if state == "" {
		c.Error(errors.New("state is missing"))
		c.JSON(400, gin.H{"error": "State is missing"})
		return
	}

	pcc, err := protocol.ParseCredentialCreationResponseBody(c.Request.Body)
	if err != nil {
		c.Error(err)
		panic(err)
	}

	err = auth.FinishFido2Register(state, user, pcc)
	if err != nil {
		c.Error(err)
		panic(err)
	}

	c.JSON(200, gin.H{"success": true})
}

func unlinkFido2(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	name := c.Param("name")
	if name == "" {
		c.Error(errors.New("name is missing"))
		c.JSON(400, gin.H{"error": "Name is missing"})
		return
	}

	err := auth.DeleteFido2Login(user, user.ID, name)
	if err != nil {
		c.Error(err)
		panic(err)
	}

	c.JSON(200, gin.H{"success": true})
}

func getFido2Links(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		c.JSON(401, gin.H{"error": "Unauthorized"})
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
