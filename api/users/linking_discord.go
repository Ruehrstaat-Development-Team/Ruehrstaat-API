package users

import (
	"errors"
	"net/http"
	"os"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/auth/discord"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"time"

	"github.com/gin-gonic/gin"
)

func beginDiscordLink(c *gin.Context) {
	user := auth.Extract(c)
	if user == nil {
		c.Error(auth.ErrInvalidToken)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	if user.DiscordId != nil {
		c.Error(errors.New("discord is already linked"))
		c.JSON(400, gin.H{"error": "Discord is already linked"})
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
		c.Error(errors.New("state is missing"))
		c.JSON(400, gin.H{"error": "State is missing"})
		return
	}

	code := c.Query("code")
	if code == "" {
		c.Error(errors.New("code is missing"))
		c.JSON(400, gin.H{"error": "Code is missing"})
		return
	}

	payload := struct {
		RedirectTo   string `json:"redirect_to"`
		UserId       string `json:"user_id"`
		CodeVerifier string `json:"code_verifier"`
	}{}
	if !cache.EndState("user_discord_link", state, &payload) {
		c.Error(errors.New("invalid state"))
		c.JSON(400, gin.H{"error": "Invalid state"})
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
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	if user.DiscordId == nil {
		c.Error(errors.New("discord is not linked"))
		c.JSON(400, gin.H{"error": "Discord is not linked"})
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
