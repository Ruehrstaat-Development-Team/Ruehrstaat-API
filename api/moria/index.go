package moria

import (
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/serialize"
	"ruehrstaat-backend/services/moria"

	"github.com/gin-gonic/gin"
)

var log = logging.Logger{Package: "api/moria"}

func RegisterRoutes(api *gin.RouterGroup) {
	moriaApi := api.Group("/moria")

	moriaApi.GET("/info", getMoriaInfo)
}

func getMoriaInfo(c *gin.Context) {
	if _, err := auth.RequireSessionBoundAuth(c); err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	moriaInfo := moria.GetMoriaInfo()
	if moriaInfo == nil {
		errors.ReturnWithError(c, moria.ErrMoriaDisabled)
		return
	}

	serialize.JSON[moria.MoriaInfo](c, (&serialize.MoriaInfoSerializer{}).ParseFlags(c), *moriaInfo)
}
