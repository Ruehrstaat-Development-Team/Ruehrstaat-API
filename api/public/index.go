package public

import (
	"ruehrstaat-backend/logging"

	"github.com/gin-gonic/gin"
)

var log = logging.Logger{Package: "api/public"}

func RegisterRoutes(api *gin.RouterGroup) {
	publicApi := api.Group("/public")

	publicCarrierApi := publicApi.Group("/carrier")
	publicCarrierApi.GET("/:id", publicGetCarrier)

}
