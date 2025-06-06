package serialize

import (
	"ruehrstaat-backend/db/entities"

	"github.com/gin-gonic/gin"
)

type UserSerializer struct {
	// Whether to include the full user object (true) or just specific fields
	Full    bool `json:"full"`
	Limited bool `json:"limited"`
}

func (s *UserSerializer) Serialize(user entities.User) interface{} {
	if s.Limited {
		return &JsonObj{
			"cmdrName":     user.CmdrName,
			"squadronRank": user.SquadronRank,
		}
	}
	obj := &JsonObj{
		"id":               user.ID,
		"email":            user.Email,
		"nickname":         user.Nickname,
		"cmdrName":         user.CmdrName,
		"isActivated":      user.IsActivated,
		"isTotpJustActive": user.OtpActive && !user.OtpVerified,
		"hasTotp":          user.HasTwoFactor(),
		"linkedDiscord":    user.DiscordName,
		"squadronRank":     user.SquadronRank,
		"isSquadronMember": user.IsSquadronMember,
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

type UsersBySquadronRankSerializer struct{}

func (s *UsersBySquadronRankSerializer) Serialize(usersBySquadronRank entities.UsersBySquadronRank) interface{} {
	obj := &JsonObj{
		"squadronRank": usersBySquadronRank.SquadronRank,
		"users":        DoArray[entities.User](&UserSerializer{Limited: true, Full: false}, usersBySquadronRank.Users),
	}
	return obj
}

func (s *UsersBySquadronRankSerializer) ParseFlags(c *gin.Context) *UsersBySquadronRankSerializer {
	return s
}
