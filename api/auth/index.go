package auth

import (
	"encoding/base64"
	"net/http"
	"os"
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/auth/discord"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	jsoniter "github.com/json-iterator/go"
)

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

	err := auth.Register(dto.Email, dto.Password, dto.Nickname, dto.CmdrName, false)
	if err == auth.ErrInvalidEmail {
		errors.ReturnWithError(c, err)
		return
	}

	if err == auth.ErrEmailTaken {
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
	dto := &loginBody{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	token, user, err := auth.Login(dto.Email, dto.Password, dto.Otp)
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
		otpState := cache.BeginState("login_otp", map[string]string{
			"email":    dto.Email,
			"password": dto.Password,
		}, time.Minute*3)

		c.JSON(err.HtmlCode(), gin.H{
			"error": err.Message(),
			"code":  err.Code(),
			"name":  err.Nickname(),
			"state": otpState,
		})
		return
	}

	if err == auth.ErrUserOtpWrong {
		c.Error(err.Error())

		errors.ReturnWithError(c, auth.ErrInvalidCredentials)
		return
	}

	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.SetCookie("refresh_token", token.RefreshToken, 60*60*24*30, "/", "", false, true)
	c.JSON(200, token)
}

func loginTotp(c *gin.Context) {
	dto := &loginTotpBody{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	var payload map[string]string
	if ok := cache.EndState("login_otp", dto.State, &payload); !ok {
		errors.ReturnWithError(c, auth.ErrInvalidState)
		return
	}

	token, user, err := auth.Login(payload["email"], payload["password"], &dto.Code)
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

	if err == auth.ErrUserOtpWrong {
		c.Error(err.Error())
		otpState := cache.BeginState("login_otp", map[string]string{
			"email":    payload["email"],
			"password": payload["password"],
		}, time.Minute*3)

		c.JSON(err.HtmlCode(), gin.H{
			"error": err.Message(),
			"state": otpState,
			"code":  err.Code(),
			"name":  err.Nickname(),
		})
		return
	}

	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.SetCookie("refresh_token", token.RefreshToken, 60*60*24*30, "/", "", false, true)
	c.JSON(200, token)
}

func refreshToken(c *gin.Context) {
	refreshToken, cerr := c.Cookie("refresh_token")
	if cerr != nil {
		c.Error(cerr)
		c.Error(dtoerr.InvalidDTO.Error())
		return
	}

	token, err := auth.Refresh(refreshToken)
	if err == auth.ErrUsedRefreshToken {
		c.Error(err.Error())
		errors.ReturnWithError(c, auth.ErrInvalidToken)
		return
	}

	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.SetCookie("refresh_token", token.RefreshToken, 60*60*24*30, "/", "", false, true)
	c.JSON(200, token)
}

func logout(c *gin.Context) {
	refreshToken, cerr := c.Cookie("refresh_token")
	if cerr != nil {
		c.Error(cerr)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	err := auth.Logout(refreshToken, false)
	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
	c.JSON(200, gin.H{"message": "User logged out successfully"})
}

func logoutAll(c *gin.Context) {
	refreshToken, cerr := c.Cookie("refresh_token")
	if cerr != nil {
		c.Error(cerr)
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	err := auth.Logout(refreshToken, true)
	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
	c.JSON(200, gin.H{"message": "User logged out successfully"})
}

func beginDiscordLogin(c *gin.Context) {
	redirectTo := c.Query("redirect_to")
	if redirectTo == "" {
		errors.ReturnWithError(c, auth.ErrRedirectUrlMissing)
		return
	}

	codeVerifier, err := discord.GenerateCodeVerifier()
	if err != nil {
		c.Error(err)
		panic(err)
	}

	payload := struct {
		RedirectTo   string `json:"redirect_to"`
		CodeVerifier string `json:"code_verifier"`
	}{redirectTo, codeVerifier}

	state := cache.BeginState("user_discord_login", payload, time.Minute*5)
	url := discord.GetOAuthUrl(discord.LoginConf, state, codeVerifier)

	c.JSON(200, gin.H{"url": url})
}

func discordLoginCallback(c *gin.Context) {
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
		CodeVerifier string `json:"code_verifier"`
	}{}

	if !cache.EndState("user_discord_login", state, &payload) {
		errors.ReturnWithError(c, auth.ErrInvalidState)
		return
	}

	getRedirect := func(suffix string) string {
		if strings.Contains(payload.RedirectTo, "?") {
			return payload.RedirectTo + "&" + suffix
		}

		return payload.RedirectTo + "?" + suffix
	}

	ok, discordUser := discord.RetrieveOAuthUser(discord.LoginConf, state, code, payload.CodeVerifier)
	if !ok {
		c.Redirect(http.StatusTemporaryRedirect, getRedirect("success=false"))
		return
	}

	user := &entities.User{}
	if res := db.DB.Where("discord_id = ?", discordUser.ID).First(user); res.Error != nil {
		c.Redirect(http.StatusTemporaryRedirect, getRedirect("success=false"))
		return
	}

	if err := auth.CheckUserLoginAllowance(user); err != nil {
		c.Redirect(http.StatusTemporaryRedirect, getRedirect("success=false"))
		return
	}

	token, err := auth.CreateTokenPairForUser(user)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, getRedirect("success=false"))
		return
	}

	tokenJson, err2 := jsoniter.Marshal(token)
	if err2 != nil {
		c.Redirect(http.StatusTemporaryRedirect, getRedirect("success=false"))
		return
	}

	b64Token := base64.StdEncoding.EncodeToString(tokenJson)

	c.SetCookie("refresh_token", token.RefreshToken, 60*60*24*30, "/", "", false, true)
	c.Redirect(http.StatusTemporaryRedirect, getRedirect("success=true&tokend="+b64Token))
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
	state := c.Query("state")
	if state == "" {
		errors.ReturnWithError(c, auth.ErrStateIsMissing)
		return
	}

	pcc, perr := protocol.ParseCredentialRequestResponseBody(c.Request.Body)
	if perr != nil {
		c.Error(perr)
		panic(perr)
	}

	user, err := auth.FinishFido2Login(state, pcc)
	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	token, err := auth.CreateTokenPairForUser(user)
	if err != nil {
		c.Error(err.Error())
		panic(err)
	}

	c.SetCookie("refresh_token", token.RefreshToken, 60*60*24*30, "/", "", false, true)
	c.JSON(200, token)
}
