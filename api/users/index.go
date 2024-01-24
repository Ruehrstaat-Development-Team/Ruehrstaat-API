package users

import (
	"ruehrstaat-backend/logging"

	"github.com/gin-gonic/gin"
)

var log = logging.Logger{Package: "api-users"}

func RegisterRoutes(api *gin.RouterGroup) {
	usersApi := api.Group("/users")

	usersApi.GET("/:id", getUser)
	usersApi.PATCH("/:id", editUser)
	usersApi.POST("/:id/activate", activateUser)
	usersApi.POST("/activation/resend", resendUserActivation)
	usersApi.POST("/password-reset/request", requestPasswordReset)
	usersApi.PUT("/:id/password-reset", resetPassword)
	usersApi.PATCH("/password", changePassword)
	usersApi.POST("/link/discord", beginDiscordLink)
	usersApi.GET("/link/discord/callback", discordLinkCallback)
	usersApi.DELETE("/link/discord", unlinkDiscord)
	usersApi.POST("/link/fido2/begin", beginFido2Link)
	usersApi.POST("/link/fido2/end", endFido2Link)
	usersApi.GET("/link/fido2/all", getFido2Links)
	usersApi.DELETE("/link/fido2/:name", unlinkFido2)
	usersApi.POST("/totp", beginTotp)
	usersApi.POST("/totp/verify", verifyTotp)
	usersApi.GET("/totp/verify/url", requestUrlForVerification)
	usersApi.POST("/totp/disable", disableTotp)
	usersApi.DELETE("/:id/totp", removeTotp)
	usersApi.POST("/change-email/request", requestEmailChange)
	usersApi.POST("/:id/change-email", changeEmail)
	usersApi.PATCH("/locale", setLocale)

	adminGroup := usersApi.Group("/admin")
	adminGroup.GET("/", adminGetUsers)
	adminGroup.POST("/", adminCreateUser)
}
