package auth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/auth/discord"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
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
		c.Error(errors.New("registration is disabled"))
		c.JSON(403, gin.H{"error": "Registration is disabled"})
		return
	}

	dto := &registerBody{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": "Given data is invalid"})
		return
	}

	err := auth.Register(dto.Email, dto.Password, dto.Nickname, dto.CmdrName, false)
	if err == auth.ErrInvalidEmail {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Invalid email"})
		return
	}

	if err == auth.ErrEmailTaken {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Email is already taken"})
		return
	}

	if err != nil {
		c.Error(err)
		panic(err)
	}

	c.JSON(200, gin.H{"message": "User created successfully"})
}

func login(c *gin.Context) {
	dto := &loginBody{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": "Given data is invalid"})
		return
	}

	token, user, err := auth.Login(dto.Email, dto.Password, dto.Otp)
	if err == auth.ErrUserNotFound {
		c.Error(err)
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	if err == auth.ErrInvalidCredentials {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Invalid password"})
		return
	}

	if err == auth.ErrUserBanned {
		c.Error(err)
		c.JSON(403, gin.H{"error": "User is banned"})
		return
	}

	if err == auth.ErrUserNotActivated {
		c.Error(err)
		activateState := cache.BeginState("resend_activate", user.ID, time.Minute*5)

		c.JSON(409, gin.H{
			"error": "User is not activated",
			"state": activateState,
		})
		return
	}

	if err == auth.ErrUserOtpMissing {
		c.Error(err)
		otpState := cache.BeginState("login_otp", map[string]string{
			"email":    dto.Email,
			"password": dto.Password,
		}, time.Minute*3)

		c.JSON(428, gin.H{
			"error": "OTP is missing",
			"state": otpState,
		})
		return
	}

	if err == auth.ErrUserOtpWrong {
		c.Error(err)

		c.JSON(428, gin.H{
			"error": "Login credentials are wrong",
		})
		return
	}

	if err != nil {
		c.Error(err)
		panic(err)
	}

	c.SetCookie("refresh_token", token.RefreshToken, 60*60*24*30, "/", "", false, true)
	c.JSON(200, token)
}

func loginTotp(c *gin.Context) {
	dto := &loginTotpBody{}
	if err := c.ShouldBindJSON(dto); err != nil {
		c.Error(err)
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": "Given data is invalid"})
		return
	}

	var payload map[string]string
	if ok := cache.EndState("login_otp", dto.State, &payload); !ok {
		c.Error(errors.New("invalid state"))
		c.JSON(400, gin.H{"error": "Invalid state"})
		return
	}

	token, user, err := auth.Login(payload["email"], payload["password"], &dto.Code)
	if err == auth.ErrUserNotFound {
		c.Error(err)
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	if err == auth.ErrInvalidCredentials {
		c.Error(err)
		c.JSON(400, gin.H{"error": "Invalid password"})
		return
	}

	if err == auth.ErrUserBanned {
		c.Error(err)
		c.JSON(403, gin.H{"error": "User is banned"})
		return
	}

	if err == auth.ErrUserNotActivated {
		c.Error(err)
		activateState := cache.BeginState("resend_activate", user.ID, time.Minute*5)

		c.JSON(409, gin.H{
			"error": "User is not activated",
			"state": activateState,
		})
		return
	}

	if err == auth.ErrUserOtpWrong {
		c.Error(err)
		otpState := cache.BeginState("login_otp", map[string]string{
			"email":    payload["email"],
			"password": payload["password"],
		}, time.Minute*3)

		c.JSON(428, gin.H{
			"error": "OTP is wrong",
			"state": otpState,
		})
		return
	}

	if err != nil {
		c.Error(err)
		panic(err)
	}

	c.SetCookie("refresh_token", token.RefreshToken, 60*60*24*30, "/", "", false, true)
	c.JSON(200, token)
}

func refreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.Error(err)
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": "Refresh token is missing"})
		return
	}

	token, err := auth.Refresh(refreshToken)
	if err == auth.ErrUsedRefreshToken {
		c.JSON(400, gin.H{"error": "Token invalid"})
		return
	}

	if err != nil {
		c.Error(err)
		panic(err)
	}

	c.SetCookie("refresh_token", token.RefreshToken, 60*60*24*30, "/", "", false, true)
	c.JSON(200, token)
}

func logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.Error(err)
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": "Refresh token is missing"})
		return
	}

	err = auth.Logout(refreshToken, false)
	if err != nil {
		c.Error(err)
		panic(err)
	}

	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
	c.JSON(200, gin.H{"message": "User logged out successfully"})
}

func logoutAll(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.Error(err)
		c.Error(dtoerr.InvalidDTO)
		c.JSON(400, gin.H{"error": "Refresh token is missing"})
		return
	}

	err = auth.Logout(refreshToken, true)
	if err != nil {
		c.Error(err)
		panic(err)
	}

	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
	c.JSON(200, gin.H{"message": "User logged out successfully"})
}

func beginDiscordLogin(c *gin.Context) {
	redirectTo := c.Query("redirect_to")
	if redirectTo == "" {
		c.Error(errors.New("redirect URL is missing"))
		c.JSON(400, gin.H{"error": "Redirect URL is missing"})
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
		CodeVerifier string `json:"code_verifier"`
	}{}

	if !cache.EndState("user_discord_login", state, &payload) {
		c.Error(errors.New("invalid state"))
		c.JSON(400, gin.H{"error": "Invalid state"})
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

	tokenJson, err := jsoniter.Marshal(token)
	if err != nil {
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
		c.Error(err)
		panic(err)
	}

	c.JSON(200, gin.H{"state": state, "options": options})
}

func endLoginFido2(c *gin.Context) {
	state := c.Query("state")
	if state == "" {
		c.Error(errors.New("state is missing"))
		c.JSON(400, gin.H{"error": "State is missing"})
		return
	}

	pcc, err := protocol.ParseCredentialRequestResponseBody(c.Request.Body)
	if err != nil {
		c.Error(err)
		panic(err)
	}

	user, err := auth.FinishFido2Login(state, pcc)
	if err != nil {
		c.Error(err)
		panic(err)
	}

	token, err := auth.CreateTokenPairForUser(user)
	if err != nil {
		c.Error(err)
		panic(err)
	}

	c.SetCookie("refresh_token", token.RefreshToken, 60*60*24*30, "/", "", false, true)
	c.JSON(200, token)
}
