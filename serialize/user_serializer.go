package serialize

import (
	"ruehrstaat-backend/db/entities"

	"github.com/gin-gonic/gin"
)

type UserSerializer struct {
	// Whether to include the full user object (true) or just specific fields
	Full bool `json:"full"`
}

func (s *UserSerializer) Serialize(user entities.User) interface{} {
	obj := &JsonObj{
		"id":               user.ID,
		"email":            user.Email,
		"nickname":         user.Nickname,
		"cmdrName":         user.CmdrName,
		"isActivated":      user.IsActivated,
		"isTotpJustActive": user.OtpActive && !user.OtpVerified,
		"hasTotp":          user.HasTwoFactor(),
		"linkedDiscord":    user.DiscordName,
	}
	if s.Full {
		obj.Add("isAdmin", user.IsAdmin)
		obj.Add("isBanned", user.IsBanned)
	}

	return obj
}

func (s *UserSerializer) ParseFlags(c *gin.Context) *UserSerializer {
	s.Full = c.Query("full") == "true"
	return s
}
