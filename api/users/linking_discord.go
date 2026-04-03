package users

import (
	"net/http"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/auth/discord"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/services/user_service"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"ruehrstaat-backend/util"
)

const discordLinkBindingCookieName = "discord_link_binding"

func setDiscordLinkBindingCookie(c *gin.Context, value string, maxAge int) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(discordLinkBindingCookieName, value, maxAge, "/v1/users/link/discord", "", auth.RequestUsesSecureTransport(c.Request), true)
}

func issueDiscordLinkBinding(c *gin.Context) string {
	binding, err := util.GenerateRandomString(32)
	if err != nil {
		panic(err)
	}
	setDiscordLinkBindingCookie(c, binding, int((5 * time.Minute).Seconds()))
	return binding
}

func clearDiscordLinkBinding(c *gin.Context) {
	setDiscordLinkBindingCookie(c, "", -1)
}

func hasDiscordLinkBinding(c *gin.Context, expected string) bool {
	if expected == "" {
		return false
	}
	current, err := c.Cookie(discordLinkBindingCookieName)
	if err != nil {
		return false
	}
	return current == expected
}

func hasFreshDiscordLinkCallbackSession(liveUser *entities.User, liveSession *entities.RefreshToken, expectedUserID uuid.UUID, expectedSessionID uuid.UUID, now time.Time) bool {
	if liveUser == nil || liveSession == nil {
		return false
	}
	if liveUser.ID != expectedUserID || liveSession.ID != expectedSessionID {
		return false
	}
	return liveSession.AuthTime.Add(auth.FreshBrowserSessionMaxAge).After(now)
}

func isBrowserNavigationRequest(c *gin.Context) bool {
	if c.Request.Method != http.MethodGet {
		return false
	}
	if strings.EqualFold(c.GetHeader("Sec-Fetch-Mode"), "navigate") {
		return true
	}
	accept := strings.ToLower(c.GetHeader("Accept"))
	return strings.Contains(accept, "text/html")
}

func redirectDiscordLinkCallbackFailure(c *gin.Context, redirectTo string) bool {
	target, err := auth.NormalizeFrontendRedirectTarget(redirectTo, true)
	if err != nil {
		target, err = auth.NormalizeFrontendRedirectTarget("", true)
		if err != nil {
			return false
		}
	}

	clearDiscordLinkBinding(c)
	c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(target, map[string]string{"success": "false", "rs": "1"}))
	return true
}

func handleDiscordLinkCallbackFailure(c *gin.Context, redirectTo string, rstErr *errors.RstError) {
	if isBrowserNavigationRequest(c) && redirectDiscordLinkCallbackFailure(c, redirectTo) {
		return
	}
	errors.ReturnWithError(c, rstErr)
}

func beginDiscordLink(c *gin.Context) {
	user, session, authErr := auth.RequireFreshBrowserSession(c)
	if authErr != nil {
		c.Error(authErr.Error())
		errors.ReturnWithError(c, authErr)
		return
	}

	if user.DiscordId != nil {
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventDiscordLinkFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "already_linked"})
		errors.ReturnWithError(c, auth.ErrDiscordAlreadyLinked)
		return
	}

	redirectTo, redirectErr := auth.NormalizeFrontendRedirectTarget(c.Query("redirect_to"), true)
	if redirectErr != nil {
		errors.ReturnWithError(c, redirectErr)
		return
	}

	codeVerifier, err := discord.GenerateCodeVerifier()
	if err != nil {
		panic(err)
	}

	payload := map[string]interface{}{
		"redirect_to":     redirectTo,
		"user_id":         user.ID,
		"session_id":      session.ID,
		"code_verifier":   codeVerifier,
		"browser_binding": issueDiscordLinkBinding(c),
	}

	state := cache.BeginState("user_discord_link", payload, time.Minute*5)
	url := discord.GetOAuthUrl(discord.LinkingConf, state, codeVerifier)

	c.JSON(200, gin.H{"url": url})
}

func discordLinkCallback(c *gin.Context) {
	state := c.Query("state")
	if state == "" {
		handleDiscordLinkCallbackFailure(c, "", auth.ErrStateIsMissing)
		return
	}

	code := c.Query("code")
	if code == "" {
		handleDiscordLinkCallbackFailure(c, "", auth.ErrCodeIsMissing)
		return
	}

	payload := struct {
		RedirectTo     string `json:"redirect_to"`
		UserId         string `json:"user_id"`
		SessionID      string `json:"session_id"`
		CodeVerifier   string `json:"code_verifier"`
		BrowserBinding string `json:"browser_binding"`
	}{}
	if !cache.GetState("user_discord_link", state, &payload) {
		handleDiscordLinkCallbackFailure(c, "", auth.ErrInvalidState)
		return
	}

	redirectTo, redirectErr := auth.NormalizeFrontendRedirectTarget(payload.RedirectTo, true)
	if redirectErr != nil {
		handleDiscordLinkCallbackFailure(c, "", redirectErr)
		return
	}
	parsedUserID, userIDErr := uuid.Parse(payload.UserId)
	parsedSessionID, sessionIDErr := uuid.Parse(payload.SessionID)
	if userIDErr != nil || sessionIDErr != nil {
		handleDiscordLinkCallbackFailure(c, redirectTo, auth.ErrInvalidState)
		return
	}

	if !hasDiscordLinkBinding(c, payload.BrowserBinding) {
		clearDiscordLinkBinding(c)
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventDiscordLinkFailed, UserID: &parsedUserID, IPAddress: c.ClientIP(), Success: false, ErrorReason: "session_mismatch"})
		c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "false", "rs": "1"}))
		return
	}

	liveUser, liveSession, authErr := auth.RequireCurrentBrowserSession(c)
	if authErr != nil || !hasFreshDiscordLinkCallbackSession(liveUser, liveSession, parsedUserID, parsedSessionID, time.Now()) {
		clearDiscordLinkBinding(c)
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventDiscordLinkFailed, UserID: &parsedUserID, IPAddress: c.ClientIP(), Success: false, ErrorReason: "session_mismatch"})
		c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "false", "rs": "1"}))
		return
	}

	consumedPayload := struct {
		RedirectTo     string `json:"redirect_to"`
		UserId         string `json:"user_id"`
		SessionID      string `json:"session_id"`
		CodeVerifier   string `json:"code_verifier"`
		BrowserBinding string `json:"browser_binding"`
	}{}
	if !cache.EndState("user_discord_link", state, &consumedPayload) || consumedPayload.UserId != payload.UserId || consumedPayload.SessionID != payload.SessionID || consumedPayload.BrowserBinding != payload.BrowserBinding {
		handleDiscordLinkCallbackFailure(c, redirectTo, auth.ErrInvalidState)
		return
	}

	ok, discordUser := discord.RetrieveOAuthUser(discord.LinkingConf, state, code, consumedPayload.CodeVerifier)
	if !ok {
		clearDiscordLinkBinding(c)
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventDiscordLinkFailed, UserID: &parsedUserID, IPAddress: c.ClientIP(), Success: false, ErrorReason: "oauth_failed"})
		c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "false", "rs": "1"}))
		return
	}

	discordName := discordUser.Username + "#" + discordUser.Discriminator
	var userID uuid.UUID
	var userEmail string
	err := user_service.WithLockedUser(c.Request.Context(), db.DB, liveUser.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		userID = lockedUser.ID
		userEmail = lockedUser.Email
		if lockedUser.DiscordId != nil {
			return auth.ErrDiscordAlreadyLinked.Error()
		}
		lockedUser.DiscordId = &discordUser.ID
		lockedUser.DiscordName = &discordName
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "DiscordId", "DiscordName")
	})
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			clearDiscordLinkBinding(c)
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventDiscordLinkFailed, UserID: &parsedUserID, IPAddress: c.ClientIP(), Success: false, ErrorReason: "user_not_found"})
			c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "false", "rs": "1"}))
			return
		}
		if err.Error() == auth.ErrDiscordAlreadyLinked.String() {
			clearDiscordLinkBinding(c)
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventDiscordLinkFailed, UserID: &userID, Email: userEmail, IPAddress: c.ClientIP(), Success: false, ErrorReason: "already_linked", Details: map[string]any{"discord_id": discordUser.ID, "discord_name": discordName}})
			c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "false", "rs": "1"}))
			return
		}
		clearDiscordLinkBinding(c)
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventDiscordLinkFailed, UserID: &parsedUserID, IPAddress: c.ClientIP(), Success: false, ErrorReason: "db_update_failed"})
		c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "false", "rs": "1"}))
		return
	}
	logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventDiscordLinked, UserID: &userID, Email: userEmail, IPAddress: c.ClientIP(), Success: true, Details: map[string]any{"discord_id": discordUser.ID, "discord_name": discordName}})

	clearDiscordLinkBinding(c)
	c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "true", "rs": "1"}))
}

func unlinkDiscord(c *gin.Context) {
	user, _, authErr := auth.RequireFreshBrowserSession(c)
	if authErr != nil {
		c.Error(authErr.Error())
		errors.ReturnWithError(c, authErr)
		return
	}

	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		if lockedUser.DiscordId == nil {
			return auth.ErrDiscordNotLinked.Error()
		}
		lockedUser.DiscordId = nil
		lockedUser.DiscordName = nil
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "DiscordId", "DiscordName")
	}); err != nil {
		if err.Error() == auth.ErrDiscordNotLinked.String() {
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventDiscordUnlinkFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "not_linked"})
			errors.ReturnWithError(c, auth.ErrDiscordNotLinked)
			return
		}
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventDiscordUnlinkFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "db_update_failed"})
		c.Error(err)
		panic(err)
	}
	logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventDiscordUnlinked, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: true})

	c.JSON(200, gin.H{"success": true})
}
