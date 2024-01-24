package carrier

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/serialize"

	"github.com/gin-gonic/gin"
)

func getAllCarriers(c *gin.Context) {
	user := c.MustGet("user").(*entities.User)
	tokenValue, exists := c.Get("token")
	token := &entities.ApiToken{}
	if exists {
		token = tokenValue.(*entities.ApiToken)
	}

	carriers := []entities.Carrier{}

	if user.IsAdmin || (token != nil && token.HasFullReadAccess) {
		if res := db.DB.Find(&carriers); res.Error != nil {
			c.JSON(500, gin.H{"error": "Internal Server Error"})
			return
		}
	} else {
		// get carrier where owner id is user id
		if res := db.DB.Where("owner_id = ?", user.ID).Find(&carriers); res.Error != nil {
			c.JSON(500, gin.H{"error": "Internal Server Error"})
			return
		}

		// if token is not nil, get append carriers where id is in token.HadReadAccessTo
		if token != nil {
			addtionalCarriers := []entities.Carrier{}
			if res := db.DB.Where("id IN (?)", token.HasReadAccessTo).Find(&addtionalCarriers); res.Error != nil {
				c.JSON(500, gin.H{"error": "Internal Server Error"})
				return
			}
			carriers = append(carriers, addtionalCarriers...)
		}
	}

	serialize.JSONArray[entities.Carrier](c, (&serialize.CarrierSerializer{}).ParseFlags(c), carriers)
}

func getCarrier(c *gin.Context) {
	user := c.MustGet("user").(*entities.User)
	tokenValue, exists := c.Get("token")
	token := &entities.ApiToken{}
	if exists {
		token = tokenValue.(*entities.ApiToken)
	}

	carrierId := c.Param("id")
	if carrierId == "" {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	carrier := entities.Carrier{}
	if res := db.DB.Where("id = ?", carrierId).First(&carrier); res.Error != nil {
		if !user.IsAdmin {
			c.JSON(403, gin.H{"error": "Forbidden"})
			return
		}
		c.JSON(404, gin.H{"error": "Carrier not found"})
		return
	}

	if !user.IsAdmin && (token == nil || !token.HasFullReadAccess) {
		if *carrier.OwnerID != user.ID && !token.HasReadAccessToCarrier(carrier.ID) {
			c.JSON(403, gin.H{"error": "Forbidden"})
			return
		}
	}

	serialize.JSON[entities.Carrier](c, (&serialize.CarrierSerializer{}).ParseFlags(c), carrier)
}
