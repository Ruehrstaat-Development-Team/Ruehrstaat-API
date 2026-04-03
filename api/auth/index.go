package auth

import (
	"net/http"
	"net/url"
	"os"
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/auth/discord"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/services/locale"
	"ruehrstaat-backend/util"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
)

const discordLoginBindingCookieName = "discord_login_binding"
const discordLoginCallbackFallbackPath = "auth/callbacks/discord"

func setRefreshTokenCookie(c *gin.Context, value string, maxAge int) {
	c.SetSameSite(auth.RefreshCookieSameSiteMode(c.Request))
	c.SetCookie("refresh_token", value, maxAge, "/", "", auth.RequestUsesSecureTransport(c.Request), true)
}

func clearRefreshTokenCookie(c *gin.Context) {
	setRefreshTokenCookie(c, "", -1)
}

func beginLoginOtpState(userID string, passwordHash string) string {
	return cache.BeginState("login_otp", map[string]string{
		"user_id":       userID,
		"password_hash": passwordHash,
	}, time.Minute*3)
}

func nextLoginOtpState(currentState string, userID string, passwordHash string, err *errors.RstError) string {
	if err == auth.ErrUserOtpRateLimited {
		return currentState
	}

	cache.DeleteState("login_otp", currentState)
	if err == auth.ErrUserOtpWrong {
		return beginLoginOtpState(userID, passwordHash)
	}

	return ""
}

func writeSessionTokenResponse(c *gin.Context, token *auth.TokenPair) {
	setRefreshTokenCookie(c, token.RefreshToken, 60*60*24*30)
	c.JSON(http.StatusOK, token)
}

func setDiscordLoginBindingCookie(c *gin.Context, value string, maxAge int) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(discordLoginBindingCookieName, value, maxAge, "/v1/auth/discord", "", auth.RequestUsesSecureTransport(c.Request), true)
}

func issueDiscordLoginBinding(c *gin.Context) string {
	binding, err := util.GenerateRandomString(32)
	if err != nil {
		panic(err)
	}
	setDiscordLoginBindingCookie(c, binding, int((5 * time.Minute).Seconds()))
	return binding
}

func clearDiscordLoginBinding(c *gin.Context) {
	setDiscordLoginBindingCookie(c, "", -1)
}

func hasDiscordLoginBinding(c *gin.Context, expected string) bool {
	if expected == "" {
		return false
	}
	current, err := c.Cookie(discordLoginBindingCookieName)
	if err != nil {
		return false
	}
	return current == expected
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

func discordLoginCallbackFallbackPathForRequest(c *gin.Context) string {
	referer := strings.TrimSpace(c.GetHeader("Referer"))
	if referer == "" {
		return discordLoginCallbackFallbackPath
	}

	normalizedReferer, err := auth.NormalizeFrontendRedirectTarget(referer, false)
	if err != nil {
		return discordLoginCallbackFallbackPath
	}

	frontendBase, err := auth.NormalizeFrontendRedirectTarget("", true)
	if err != nil {
		return discordLoginCallbackFallbackPath
	}

	refererURL, parseErr := url.Parse(normalizedReferer)
	if parseErr != nil {
		return discordLoginCallbackFallbackPath
	}
	frontendBaseURL, parseErr := url.Parse(frontendBase)
	if parseErr != nil {
		return discordLoginCallbackFallbackPath
	}

	basePath := strings.TrimSuffix(frontendBaseURL.Path, "/")
	relativePath := strings.TrimPrefix(refererURL.Path, basePath)
	relativePath = strings.Trim(relativePath, "/")
	if relativePath == "" {
		return discordLoginCallbackFallbackPath
	}

	localeHint := strings.Split(relativePath, "/")[0]
	if !locale.DoesLocaleExist(localeHint) {
		return discordLoginCallbackFallbackPath
	}

	return localeHint + "/" + discordLoginCallbackFallbackPath
}

func redirectDiscordLoginCallbackFailure(c *gin.Context, redirectTo string) bool {
	target := ""
	err := auth.ErrInvalidRedirectUrl
	if redirectTo != "" {
		target, err = auth.NormalizeFrontendRedirectTarget(redirectTo, false)
	}
	if redirectTo == "" || err != nil {
		target, err = auth.ResolveFrontendPath(discordLoginCallbackFallbackPathForRequest(c))
		if err != nil {
			return false
		}
	}

	clearDiscordLoginBinding(c)
	c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(target, map[string]string{"success": "false"}))
	return true
}

func handleDiscordLoginCallbackFailure(c *gin.Context, redirectTo string, rstErr *errors.RstError) {
	if isBrowserNavigationRequest(c) && redirectDiscordLoginCallbackFailure(c, redirectTo) {
		return
	}
	errors.ReturnWithError(c, rstErr)
}

func RegisterRoutes(api *gin.RouterGroup) {
	authApi := api.Group("/auth")

	authApi.POST("/register", register)
	authApi.POST("/login", login)
	authApi.POST("/login/totp", loginTotp)
	authApi.POST("/login/fido2/begin", beginLoginFido2)
	authApi.POST("/login/fido2/end", endLoginFido2)
	authApi.GET("/login/discord", beginDiscordLogin)
	authApi.GET("/discord/callback", discordLoginCallback)
	authApi.POST("/refresh", refreshToken)
	authApi.POST("/logout", logout)
	authApi.POST("/logout/all", logoutAll)

	authApi.GET("/quicklogin", requestQuickLoginToken)
	authApi.PUT("/quicklogin", verifyQuickLoginToken)
	authApi.POST("/quicklogin", completeQuickLogin)

	authApi.GET("/passivelogin", requestPassiveLoginToken)
	authApi.PUT("/passivelogin", verifyPassiveLoginToken)
	authApi.POST("/passivelogin", completePassiveLogin)
}

func register(c *gin.Context) {
	if os.Getenv("REGISTRATION_DISABLED") == "true" {
		errors.ReturnWithError(c, auth.ErrRegistrationDisabled)
		return
	}

	dto := &registerBody{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	err := auth.Register(c, dto.Email, dto.Password, dto.Nickname, dto.CmdrName, false)
	if err == auth.ErrInvalidEmail || err == auth.ErrEmailTaken || err == auth.ErrPasswordTooWeak || err == auth.ErrRegistrationRateLimited {
		errors.ReturnWithError(c, err)
		return
	}

	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.JSON(200, gin.H{"message": "User created successfully"})
}

func login(c *gin.Context) {
	if err := auth.ValidateSessionEstablishingRequest(c.Request); err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	dto := &loginBody{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	token, user, err := auth.Login(c, dto.Email, dto.Password, dto.Otp)
	if err == auth.ErrUserNotFound || err == auth.ErrInvalidCredentials {
		c.Error(err.Error())
		errors.ReturnWithError(c, auth.ErrUserNotFoundOrInvalidCredentials)
		return
	}

	if err == auth.ErrUserBanned {
		errors.ReturnWithError(c, err)
		return
	}

	if err == auth.ErrUserNotActivated {
		c.Error(err.Error())
		activateState := cache.BeginState("resend_activate", user.ID, time.Minute*5)

		c.JSON(err.HtmlCode(), gin.H{
			"error": err.Message(),
			"code":  err.Code(),
			"name":  err.Nickname(),
			"state": activateState,
		})
		return
	}

	if err == auth.ErrUserOtpMissing {
		c.Error(err.Error())
		otpState := beginLoginOtpState(user.ID.String(), user.Password)

		c.JSON(err.HtmlCode(), gin.H{
			"error": err.Message(),
			"code":  err.Code(),
			"name":  err.Nickname(),
			"state": otpState,
		})
		return
	}

	if err == auth.ErrLoginRateLimited || err == auth.ErrUserOtpRateLimited {
		errors.ReturnWithError(c, err)
		return
	}

	if err == auth.ErrUserOtpWrong {
		c.Error(err.Error())
		errors.ReturnWithError(c, err)
		return
	}

	if err == auth.ErrLoginRateLimited || err == auth.ErrUserOtpRateLimited {
		errors.ReturnWithError(c, err)
		return
	}

	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	writeSessionTokenResponse(c, token)
}

func loginTotp(c *gin.Context) {
	if err := auth.ValidateSessionEstablishingRequest(c.Request); err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	dto := &loginTotpBody{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	var payload map[string]string
	if ok := cache.GetState("login_otp", dto.State, &payload); !ok {
		errors.ReturnWithError(c, auth.ErrInvalidState)
		return
	}

	token, user, err := auth.CompleteLoginWithOTP(c, payload["user_id"], payload["password_hash"], dto.Code)
	if err == auth.ErrInvalidState {
		nextLoginOtpState(dto.State, payload["user_id"], payload["password_hash"], err)
		errors.ReturnWithError(c, err)
		return
	}
	if err == auth.ErrUserNotFound || err == auth.ErrInvalidCredentials {
		nextLoginOtpState(dto.State, payload["user_id"], payload["password_hash"], err)
		c.Error(err.Error())
		errors.ReturnWithError(c, auth.ErrUserNotFoundOrInvalidCredentials)
		return
	}

	if err == auth.ErrUserBanned {
		nextLoginOtpState(dto.State, payload["user_id"], payload["password_hash"], err)
		errors.ReturnWithError(c, err)
		return
	}

	if err == auth.ErrUserNotActivated {
		nextLoginOtpState(dto.State, payload["user_id"], payload["password_hash"], err)
		c.Error(err.Error())
		activateState := cache.BeginState("resend_activate", user.ID, time.Minute*5)

		c.JSON(err.HtmlCode(), gin.H{
			"error": err.Message(),
			"code":  err.Code(),
			"name":  err.Nickname(),
			"state": activateState,
		})
		return
	}

	if isLoginTotpClientOtpError(err) {
		c.Error(err.Error())
		otpState := nextLoginOtpState(dto.State, payload["user_id"], payload["password_hash"], err)

		c.JSON(err.HtmlCode(), gin.H{
			"error": err.Message(),
			"state": otpState,
			"code":  err.Code(),
			"name":  err.Nickname(),
		})
		return
	}

	if err == auth.ErrLoginRateLimited || err == auth.ErrUserOtpRateLimited {
		nextLoginOtpState(dto.State, payload["user_id"], payload["password_hash"], err)
		errors.ReturnWithError(c, err)
		return
	}

	if err != nil {
		nextLoginOtpState(dto.State, payload["user_id"], payload["password_hash"], err)
		c.Error(err.Error())
		panic(err)
	}

	nextLoginOtpState(dto.State, payload["user_id"], payload["password_hash"], nil)
	writeSessionTokenResponse(c, token)
}

func isLoginTotpClientOtpError(err *errors.RstError) bool {
	return err == auth.ErrUserOtpWrong || err == auth.ErrUserOtpMissing
}

func refreshToken(c *gin.Context) {
	if err := auth.ValidateCookieAuthRequest(c.Request); err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	refreshToken, cerr := c.Cookie("refresh_token")
	if cerr != nil {
		c.Error(cerr)
		errors.ReturnWithError(c, auth.ErrInvalidToken)
		return
	}

	token, err := auth.Refresh(c, refreshToken)
	if err == auth.ErrUsedRefreshToken {
		c.Error(err.Error())
		errors.ReturnWithError(c, auth.ErrInvalidToken)
		return
	}
	if err == auth.ErrUserBanned {
		c.Error(err.Error())
		errors.ReturnWithError(c, err)
		return
	}

	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	writeSessionTokenResponse(c, token)
}

func logout(c *gin.Context) {
	if err := auth.ValidateCookieAuthRequest(c.Request); err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	refreshToken, cerr := c.Cookie("refresh_token")
	if cerr != nil {
		c.Error(cerr)
		clearRefreshTokenCookie(c)
		errors.ReturnWithError(c, auth.ErrInvalidToken)
		return
	}

	err := auth.Logout(c, refreshToken, false)
	if err == auth.ErrInvalidToken || err == auth.ErrInvalidAudience || err == auth.ErrUsedRefreshToken {
		clearRefreshTokenCookie(c)
		errors.ReturnWithError(c, auth.ErrInvalidToken)
		return
	}
	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	clearRefreshTokenCookie(c)
	c.JSON(200, gin.H{"message": "User logged out successfully"})
}

func logoutAll(c *gin.Context) {
	if err := auth.ValidateCookieAuthRequest(c.Request); err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	refreshToken, cerr := c.Cookie("refresh_token")
	if cerr != nil {
		c.Error(cerr)
		clearRefreshTokenCookie(c)
		errors.ReturnWithError(c, auth.ErrInvalidToken)
		return
	}

	err := auth.Logout(c, refreshToken, true)
	if err == auth.ErrInvalidToken || err == auth.ErrInvalidAudience || err == auth.ErrUsedRefreshToken {
		clearRefreshTokenCookie(c)
		errors.ReturnWithError(c, auth.ErrInvalidToken)
		return
	}
	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	clearRefreshTokenCookie(c)
	c.JSON(200, gin.H{"message": "User logged out successfully"})
}

func beginDiscordLogin(c *gin.Context) {
	redirectTo, redirectErr := auth.NormalizeFrontendRedirectTarget(c.Query("redirect_to"), false)
	if redirectErr != nil {
		errors.ReturnWithError(c, redirectErr)
		return
	}

	codeVerifier, err := discord.GenerateCodeVerifier()
	if err != nil {
		c.Error(err)
		panic(err)
	}

	payload := struct {
		RedirectTo     string `json:"redirect_to"`
		CodeVerifier   string `json:"code_verifier"`
		BrowserBinding string `json:"browser_binding"`
	}{redirectTo, codeVerifier, issueDiscordLoginBinding(c)}

	state := cache.BeginState("user_discord_login", payload, time.Minute*5)
	url := discord.GetOAuthUrl(discord.LoginConf, state, codeVerifier)

	c.JSON(200, gin.H{"url": url})
}

func discordLoginCallback(c *gin.Context) {
	state := c.Query("state")
	if state == "" {
		handleDiscordLoginCallbackFailure(c, "", auth.ErrStateIsMissing)
		return
	}

	payload := struct {
		RedirectTo     string `json:"redirect_to"`
		CodeVerifier   string `json:"code_verifier"`
		BrowserBinding string `json:"browser_binding"`
	}{}

	if !cache.GetState("user_discord_login", state, &payload) {
		handleDiscordLoginCallbackFailure(c, "", auth.ErrInvalidState)
		return
	}

	redirectTo, redirectErr := auth.NormalizeFrontendRedirectTarget(payload.RedirectTo, false)
	if redirectErr != nil {
		if isBrowserNavigationRequest(c) && redirectDiscordLoginCallbackFailure(c, "") {
			return
		}
		errors.ReturnWithError(c, redirectErr)
		return
	}

	code := c.Query("code")
	if code == "" {
		handleDiscordLoginCallbackFailure(c, redirectTo, auth.ErrCodeIsMissing)
		return
	}

	if !hasDiscordLoginBinding(c, payload.BrowserBinding) {
		handleDiscordLoginCallbackFailure(c, redirectTo, auth.ErrInvalidState)
		return
	}

	consumedPayload := struct {
		RedirectTo     string `json:"redirect_to"`
		CodeVerifier   string `json:"code_verifier"`
		BrowserBinding string `json:"browser_binding"`
	}{}
	if !cache.EndState("user_discord_login", state, &consumedPayload) {
		handleDiscordLoginCallbackFailure(c, redirectTo, auth.ErrInvalidState)
		return
	}

	ok, discordUser := discord.RetrieveOAuthUser(discord.LoginConf, state, code, consumedPayload.CodeVerifier)
	if !ok {
		clearDiscordLoginBinding(c)
		c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "false"}))
		return
	}

	user := &entities.User{}
	if res := db.DB.Where("discord_id = ?", discordUser.ID).First(user); res.Error != nil {
		c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "false"}))
		return
	}

	if err := auth.CheckUserLoginAllowance(user); err != nil {
		c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "false"}))
		return
	}

	token, err := auth.CreateTokenPairForUser(c, user)
	if err != nil {
		clearDiscordLoginBinding(c)
		c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "false"}))
		return
	}

	clearDiscordLoginBinding(c)
	setRefreshTokenCookie(c, token.RefreshToken, 60*60*24*30)
	c.Redirect(http.StatusTemporaryRedirect, auth.AppendRedirectQuery(redirectTo, map[string]string{"success": "true"}))
}

func beginLoginFido2(c *gin.Context) {
	state, options, err := auth.BeginFido2Login()
	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.JSON(200, gin.H{"state": state, "options": options})
}

func endLoginFido2(c *gin.Context) {
	if err := auth.ValidateSessionEstablishingRequest(c.Request); err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	state := c.Query("state")
	if state == "" {
		errors.ReturnWithError(c, auth.ErrStateIsMissing)
		return
	}

	pcc, perr := protocol.ParseCredentialRequestResponseBody(c.Request.Body)
	if perr != nil {
		c.Error(perr)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	user, err := auth.FinishFido2Login(c, state, pcc)
	if err != nil {
		if err == auth.ErrInvalidCredentials || err == auth.ErrUserNotFound {
			c.Error(err.Error())
			errors.ReturnWithError(c, auth.ErrUserNotFoundOrInvalidCredentials)
			return
		}

		if err == auth.ErrInvalidState || err == auth.ErrInvalidSession || err == auth.ErrInvalidUserHandle || err == auth.ErrInvalidFido2Ceremony {
			errors.ReturnWithError(c, err)
			return
		}

		c.Error(err.Error())
		panic(err)
	}

	if err := auth.CheckUserLoginAllowance(user); err != nil {
		if err == auth.ErrUserBanned {
			errors.ReturnWithError(c, err)
			return
		}

		if err == auth.ErrUserNotActivated {
			c.Error(err.Error())
			activateState := cache.BeginState("resend_activate", user.ID, time.Minute*5)

			c.JSON(err.HtmlCode(), gin.H{
				"error": err.Message(),
				"code":  err.Code(),
				"name":  err.Nickname(),
				"state": activateState,
			})
			return
		}

		c.Error(err.Error())
		panic(err)
	}

	token, err := auth.CreateTokenPairForUser(c, user)
	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventFido2LoginSuccess, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: true})
	setRefreshTokenCookie(c, token.RefreshToken, 60*60*24*30)
	c.JSON(200, token)
}
