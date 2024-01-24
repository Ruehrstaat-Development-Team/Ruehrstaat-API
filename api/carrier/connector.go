package carrier

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"

	"github.com/gin-gonic/gin"
)

const (
	CarrierJumpTypePlotted   = "jump"
	CarrierJumpTypeCancelled = "cancel"
)

type carrierJumpDto struct {
	MarketID string `json:"marketId" binding:"required"`
	Type     string `json:"type" binding:"required"`
	Body     string `json:"body" binding:"required"`
}

func carrierJump(c *gin.Context) {
	user := c.MustGet("user").(*entities.User)
	tokenValue, exists := c.Get("token")
	token := &entities.ApiToken{}
	if exists {
		token = tokenValue.(*entities.ApiToken)
	}

	// check dto
	dto := carrierJumpDto{}
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// check if type is valid
	if dto.Type != CarrierJumpTypePlotted && dto.Type != CarrierJumpTypeCancelled {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// check if carrier exists using market id
	carrier := entities.Carrier{}
	if res := db.DB.Where("market_id = ?", dto.MarketID).First(&carrier); res.Error != nil {
		if !user.IsAdmin && (token == nil || !token.HasFullWriteAccess) {
			c.JSON(403, gin.H{"error": "Forbidden"})
			return
		}
		c.JSON(404, gin.H{"error": "Not Found"})
		return
	}

	// check if user is admin or token has full write access
	if !user.IsAdmin && (token == nil || !token.HasWriteAccessToCarrier(carrier.ID)) {
		if carrier.OwnerID != nil && *carrier.OwnerID != user.ID {
			c.JSON(403, gin.H{"error": "Forbidden"})
			return
		}
	}

	// if type "jump" -> append currentLocation to LocationHistory and set CurrentLocation to new location else if type "cancel" -> remove last entry from LocationHistory and set CurrentLocation to last entry
	if dto.Type == CarrierJumpTypePlotted {
		carrier.LocationHistory = append(carrier.LocationHistory, carrier.CurrentLocation)
		carrier.CurrentLocation = dto.Body
	} else if dto.Type == CarrierJumpTypeCancelled {
		if len(carrier.LocationHistory) > 0 {
			carrier.CurrentLocation = carrier.LocationHistory[len(carrier.LocationHistory)-1]
			carrier.LocationHistory = carrier.LocationHistory[:len(carrier.LocationHistory)-1]
		}
	}

	// update carrier
	if res := db.DB.Save(&carrier); res.Error != nil {
		c.JSON(500, gin.H{"error": "Internal Server Error"})
		return
	}

	c.JSON(200, gin.H{"success": true})
}

type carrierDockingAccessDto struct {
	MarketID string `json:"marketId" binding:"required"`
	Access   string `json:"access" binding:"required"`
}

func updateCarrierDockingAccess(c *gin.Context) {
	user := c.MustGet("user").(*entities.User)
	tokenValue, exists := c.Get("token")
	token := &entities.ApiToken{}
	if exists {
		token = tokenValue.(*entities.ApiToken)
	}

	// check dto
	dto := carrierDockingAccessDto{}
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// check if carrier exists using market id
	carrier := entities.Carrier{}
	if res := db.DB.Where("market_id = ?", dto.MarketID).First(&carrier); res.Error != nil {
		if !user.IsAdmin && (token == nil || !token.HasFullWriteAccess) {
			c.JSON(403, gin.H{"error": "Forbidden"})
			return
		}
		c.JSON(404, gin.H{"error": "Not Found"})
		return
	}

	// check if user is admin or token has full write access
	if !user.IsAdmin && (token == nil || !token.HasWriteAccessToCarrier(carrier.ID)) {
		if carrier.OwnerID != nil && *carrier.OwnerID != user.ID {
			c.JSON(403, gin.H{"error": "Forbidden"})
			return
		}
	}

	// update carrier
	err := carrier.SetDockingAccess(dto.Access)
	if err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	if res := db.DB.Save(&carrier); res.Error != nil {
		c.JSON(500, gin.H{"error": "Internal Server Error"})
		return
	}

	c.JSON(200, gin.H{"success": true})
}

type carrierServiceDto struct {
	MarketID  string `json:"marketId" binding:"required"`
	Operation string `json:"operation" binding:"required"`
	Service   string `json:"service" binding:"required"`
}

func updateCarrierService(c *gin.Context) {
	user := c.MustGet("user").(*entities.User)
	tokenValue, exists := c.Get("token")
	token := &entities.ApiToken{}
	if exists {
		token = tokenValue.(*entities.ApiToken)
	}

	// check dto
	dto := carrierServiceDto{}
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// check if carrier exists using market id
	carrier := entities.Carrier{}
	if res := db.DB.Where("market_id = ?", dto.MarketID).First(&carrier); res.Error != nil {
		if !user.IsAdmin && (token == nil || !token.HasFullWriteAccess) {
			c.JSON(403, gin.H{"error": "Forbidden"})
			return
		}
		c.JSON(404, gin.H{"error": "Not Found"})
		return
	}

	// check if user is admin or token has full write access
	if !user.IsAdmin && (token == nil || !token.HasWriteAccessToCarrier(carrier.ID)) {
		if carrier.OwnerID != nil && *carrier.OwnerID != user.ID {
			c.JSON(403, gin.H{"error": "Forbidden"})
			return
		}
	}

	// update carrier
	service, exists := entities.CarrierServices[dto.Service]
	if !exists {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	switch dto.Operation {
	case "activate", "resume":
		carrier.AddService(service)
	case "deactivate", "pause":
		carrier.RemoveService(service)
	default:
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	if res := db.DB.Save(&carrier); res.Error != nil {
		c.JSON(500, gin.H{"error": "Internal Server Error"})
		return
	}

	c.JSON(200, gin.H{"success": true})
}
