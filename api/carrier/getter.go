package carrier

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/serialize"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
		if res := db.DB.Find(&carriers).Preload("Owner"); res.Error != nil {
			c.JSON(500, gin.H{"error": "Internal Server Error"})
			return
		}
	} else {
		// get carrier where owner id is user id
		if res := db.DB.Where("owner_id = ?", user.ID).Preload("Owner").Find(&carriers); res.Error != nil {
			c.JSON(500, gin.H{"error": "Internal Server Error"})
			return
		}

		// if token is not nil, get append carriers where id is in token.HadReadAccessTo
		if token != nil {
			addtionalCarriers := []entities.Carrier{}
			if res := db.DB.Where("id IN (?)", token.HasReadAccessTo).Preload("Owner").Find(&addtionalCarriers); res.Error != nil {
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
	if res := db.DB.Where("id = ?", carrierId).Preload("Owner").First(&carrier); res.Error != nil {
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

func getAllServices(c *gin.Context) {
	_, exists := c.Get("user")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	services := entities.CarrierServices
	serialize.JSONMapToArr[entities.CarrierService](c, (&serialize.CarrierServiceSerializer{}).ParseFlags(c), services)
}

func getCarrierService(c *gin.Context) {
	_, exists := c.Get("user")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	serviceId := c.Param("name")
	if serviceId == "" {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// check if service exists in map
	service, exists := entities.CarrierServices[serviceId]
	if !exists {
		c.JSON(404, gin.H{"error": "Carrier Service not found"})
		return
	}

	serialize.JSON[entities.CarrierService](c, (&serialize.CarrierServiceSerializer{}).ParseFlags(c), service)
}

// HEAD /carrier -> checks if edited since given timestamp
func checkIfEditedSince(c *gin.Context) {
	current := c.MustGet("user").(*entities.User)

	// get timestamp from query param
	timestamp := c.Query("timestamp")
	if timestamp == "" {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// parse timestamp
	timestampParsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		// check if parsing timestamp to int64 works
		timestampInt, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			c.JSON(400, gin.H{"error": "Bad Request"})
			return
		}

		timestampParsed = time.Unix(timestampInt, 0)
	}

	// check for :id in param
	carrierIdStr := c.Param("id")
	if carrierIdStr == "" {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// parse carrier id
	carrierId, err := uuid.Parse(carrierIdStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// get carrier
	carrier := entities.Carrier{}
	if res := db.DB.Where("id = ?", carrierId).First(&carrier); res.Error != nil {
		if !current.IsAdmin {
			c.JSON(403, gin.H{"error": "Forbidden"})
			return
		}
		c.JSON(404, gin.H{"error": "Carrier not found"})
		return
	}

	// check if carrier was edited since timestamp
	if carrier.UpdatedAt.After(timestampParsed) {
		c.JSON(200, gin.H{"edited": true})
		return
	}

	c.JSON(304, gin.H{"edited": false})
}
