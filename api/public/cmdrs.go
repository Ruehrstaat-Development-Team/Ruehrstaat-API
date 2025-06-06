package public

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/serialize"
	"ruehrstaat-backend/services/cmdrs"

	"github.com/gin-gonic/gin"
)

func publicGetCmdrs(c *gin.Context) {
	tmpCmdrs := []entities.User{}
	if res := db.DB.Where("is_squadron_member = ?", true).Order(entities.GetCommanderSquadronRankSortingOrder()).Find(&tmpCmdrs); res.Error != nil {
		errors.ReturnWithError(c, cmdrs.ErrInternalServerError)
		return
	}

	cmdrsBySquadronRank := map[entities.SquadronRank][]entities.User{}
	for _, cmdr := range tmpCmdrs {
		cmdrsBySquadronRank[cmdr.SquadronRank] = append(cmdrsBySquadronRank[cmdr.SquadronRank], cmdr)
	}

	cmdrsSlice := make([]entities.UsersBySquadronRank, 0, len(cmdrsBySquadronRank))
	for squadronRank, cmdrs := range cmdrsBySquadronRank {
		cmdrsSlice = append(cmdrsSlice, entities.UsersBySquadronRank{
			SquadronRank: squadronRank,
			Users:        cmdrs,
		})
	}

	serialize.JSONArray(c, &serialize.UsersBySquadronRankSerializer{}, cmdrsSlice)
}
