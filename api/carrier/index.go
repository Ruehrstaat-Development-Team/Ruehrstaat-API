package carrier

import (
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/services/carrier"

	"github.com/gin-gonic/gin"
)

var log = logging.Logger{Package: "api/carrier"}

func RegisterRoutes(api *gin.RouterGroup) {
	carrierApi := api.Group("/carrier")
	carrierApi.Use(carrierTokenAuthMiddleware())

	carrierApi.GET("/", getAllCarriers)
	carrierApi.GET("/:id", getCarrier)
	carrierApi.POST("/", createCarrier)
	carrierApi.PUT("/:id", updateCarrierOverride)
	carrierApi.PATCH("/:id", updateCarrier)
	carrierApi.HEAD("/:id", checkIfEditedSince)

	carrierApi.GET("/service", getAllServices)
	carrierApi.GET("/service/:name", getCarrierService)

	connectorApi := carrierApi.Group("/connector")
	connectorApi.PUT("/jump", carrierJump)
	connectorApi.PUT("/access", updateCarrierDockingAccess)
	connectorApi.PUT("/service", updateCarrierService)

}

func carrierTokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// check if "X-RST-User-Id" and "X-RST-Token" headers are set
		if c.GetHeader("X-RST-User-Id") != "" {
			token := auth.AuthenticateApiToken(c)
			if token == nil {
				errors.MiddlewareAbortWithError(c, carrier.ErrUnauthorized)
				return
			}

			c.Set("token", token)

			user := &entities.User{}
			if res := db.DB.Where("id = ?", &token.UserID).First(user); res.Error != nil {
				errors.MiddlewareAbortWithError(c, carrier.ErrUnauthorized)
				return
			}

			c.Set("user", user)
		} else {
			current, authorized := auth.Authorize(c)
			if !authorized {
				errors.MiddlewareAbortWithError(c, carrier.ErrUnauthorized)
				return
			}

			c.Set("user", current)
		}
	}
}
