package users

import (
	"net/http"
	"os"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/auth/discord"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"time"

	"github.com/gin-gonic/gin"
)

func beginDiscordLink(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		errors.ReturnWithError(c, auth.ErrUnauthorized)
		return
	}

	if user.DiscordId != nil {
		errors.ReturnWithError(c, auth.ErrDiscordAlreadyLinked)
		return
	}

	redirectTo := c.Query("redirect_to")
	if redirectTo == "" {
		redirectTo = os.Getenv("FRONTEND_URL")
	}

	codeVerifier, err := discord.GenerateCodeVerifier()
	if err != nil {
		panic(err)
	}

	payload := map[string]interface{}{
		"redirect_to":   redirectTo,
		"user_id":       user.ID,
		"code_verifier": codeVerifier,
	}

	state := cache.BeginState("user_discord_link", payload, time.Minute*5)
	url := discord.GetOAuthUrl(discord.LinkingConf, state, codeVerifier)

	c.JSON(200, gin.H{"url": url})
}

func discordLinkCallback(c *gin.Context) {
	state := c.Query("state")
	if state == "" {
		errors.ReturnWithError(c, auth.ErrStateIsMissing)
		return
	}

	code := c.Query("code")
	if code == "" {
		errors.ReturnWithError(c, auth.ErrCodeIsMissing)
		return
	}

	payload := struct {
		RedirectTo   string `json:"redirect_to"`
		UserId       string `json:"user_id"`
		CodeVerifier string `json:"code_verifier"`
	}{}
	if !cache.EndState("user_discord_link", state, &payload) {
		errors.ReturnWithError(c, auth.ErrInvalidState)
		return
	}

	redirectTo := payload.RedirectTo

	user := &entities.User{}
	if res := db.DB.Where("id = ?", payload.UserId).First(user); res.Error != nil {
		c.Redirect(http.StatusTemporaryRedirect, redirectTo+"?success=false&rs=1")
		return
	}

	ok, discordUser := discord.RetrieveOAuthUser(discord.LinkingConf, state, code, payload.CodeVerifier)
	if !ok {
		c.Redirect(http.StatusTemporaryRedirect, redirectTo+"?success=false&rs=1")
		return
	}

	discordName := discordUser.Username + "#" + discordUser.Discriminator
	user.DiscordId = &discordUser.ID
	user.DiscordName = &discordName

	if res := db.DB.Save(user); res.Error != nil {
		c.Redirect(http.StatusTemporaryRedirect, redirectTo+"?success=false&rs=1")
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, redirectTo+"?success=true&rs=1")
}

func unlinkDiscord(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		errors.ReturnWithError(c, auth.ErrUnauthorized)
		return
	}

	if user.DiscordId == nil {
		errors.ReturnWithError(c, auth.ErrDiscordNotLinked)
		return
	}

	user.DiscordId = nil
	user.DiscordName = nil

	if res := db.DB.Save(user); res.Error != nil {
		c.Error(res.Error)
		panic(res.Error)
	}

	c.JSON(200, gin.H{"success": true})
}
