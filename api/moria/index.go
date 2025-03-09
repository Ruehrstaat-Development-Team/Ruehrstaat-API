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
	_, authorized := auth.AutoAuthorize(c)
	if !authorized {
		return
	}

	moriaInfo := moria.GetMoriaInfo()
	if moriaInfo == nil {
		errors.ReturnWithError(c, moria.ErrMoriaDisabled)
		return
	}

	serialize.JSON[moria.MoriaInfo](c, (&serialize.MoriaInfoSerializer{}).ParseFlags(c), *moriaInfo)
}
