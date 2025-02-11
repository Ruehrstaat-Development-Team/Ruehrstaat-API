package public

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/serialize"

	"github.com/gin-gonic/gin"
)

func publicGetCarrier(c *gin.Context) {
	carrierId := c.Param("id")
	if carrierId == "" {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	carrier := entities.Carrier{}
	if res := db.DB.Where("id = ?", carrierId).Preload("Owner").First(&carrier); res.Error != nil {
		c.JSON(404, gin.H{"error": "Carrier not found"})
		return
	}

	serialize.JSON[entities.Carrier](c, &serialize.CarrierSerializer{Limited: true, Full: false}, carrier)
}

func publicGetAllCarriers(c *gin.Context) {
	carriers := []entities.Carrier{}
	if res := db.DB.Preload("Owner").Find(&carriers); res.Error != nil {
		c.JSON(404, gin.H{"error": "Carriers not found"})
		return
	}

	serialize.JSONArray(c, &serialize.CarrierSerializer{Limited: true, Full: false}, carriers)
}
