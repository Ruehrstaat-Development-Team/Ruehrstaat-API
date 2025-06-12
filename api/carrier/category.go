package carrier

import (
	"net/http"
	"ruehrstaat-backend/db/entities"

	"github.com/gin-gonic/gin"
)

func GetCategories(c *gin.Context) {
	c.JSON(http.StatusOK, entities.CarrierCategories)
}

func GetDockingAccesses(c *gin.Context) {
	c.JSON(http.StatusOK, entities.CarrierDockingAccesses)
}
