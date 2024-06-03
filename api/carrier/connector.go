package carrier

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/services/carrier"

	"github.com/gin-gonic/gin"
)

const (
	CarrierJumpTypePlotted   = "jump"
	CarrierJumpTypeCancelled = "cancel"
)

type carrierJumpDto struct {
	MarketID string `json:"marketId" binding:"required"`
	Type     string `json:"type" binding:"required"`
	Body     string `json:"body"`
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
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	// check if type is valid
	if dto.Type != CarrierJumpTypePlotted && dto.Type != CarrierJumpTypeCancelled {
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	// check if carrier exists using market id
	cr := entities.Carrier{}
	if res := db.DB.Where("market_id = ?", dto.MarketID).First(&cr); res.Error != nil {
		if !user.IsAdmin && (token == nil || !token.HasFullWriteAccess) {
			errors.ReturnWithError(c, carrier.ErrForbidden)
			return
		}
		errors.ReturnWithError(c, carrier.ErrCarrierNotFound)
		return
	}

	// check if user is admin or token has full write access
	if !user.IsAdmin && (token == nil || !token.HasWriteAccessToCarrier(cr.ID)) {
		if cr.OwnerID != nil && *cr.OwnerID != user.ID {
			errors.ReturnWithError(c, carrier.ErrForbidden)
			return
		}
	}

	// if type "jump" -> append currentLocation to LocationHistory and set CurrentLocation to new location else if type "cancel" -> remove last entry from LocationHistory and set CurrentLocation to last entry
	if dto.Type == CarrierJumpTypePlotted {
		// check if body is set
		if dto.Body == "" {
			errors.ReturnWithError(c, dtoerr.InvalidDTO)
			return
		}

		cr.LocationHistory = append(cr.LocationHistory, cr.CurrentLocation)
		cr.CurrentLocation = dto.Body
	} else if dto.Type == CarrierJumpTypeCancelled {
		if len(cr.LocationHistory) > 0 {
			cr.CurrentLocation = cr.LocationHistory[len(cr.LocationHistory)-1]
			cr.LocationHistory = cr.LocationHistory[:len(cr.LocationHistory)-1]
		}
	}

	// update carrier
	if res := db.DB.Save(&cr); res.Error != nil {
		c.Error(res.Error)
		errors.ReturnWithError(c, carrier.ErrInternalServerError)
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
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	// check if carrier exists using market id
	cr := entities.Carrier{}
	if res := db.DB.Where("market_id = ?", dto.MarketID).First(&cr); res.Error != nil {
		if !user.IsAdmin && (token == nil || !token.HasFullWriteAccess) {
			errors.ReturnWithError(c, carrier.ErrForbidden)
			return
		}
		errors.ReturnWithError(c, carrier.ErrCarrierNotFound)
		return
	}

	// check if user is admin or token has full write access
	if !user.IsAdmin && (token == nil || !token.HasWriteAccessToCarrier(cr.ID)) {
		if cr.OwnerID != nil && *cr.OwnerID != user.ID {
			errors.ReturnWithError(c, carrier.ErrForbidden)
			return
		}
	}

	// update carrier
	err := cr.SetDockingAccess(dto.Access)
	if err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	if res := db.DB.Save(&cr); res.Error != nil {
		c.Error(res.Error)
		errors.ReturnWithError(c, carrier.ErrInternalServerError)
		return
	}

	c.JSON(200, gin.H{"success": true})
}

type carrierServiceDto struct {
	MarketID  string `json:"marketId" binding:"required"`
	Operation string `json:"operation" binding:"required"` // can be "activate", "deactivate", "pause" or "resume"
	Service   string `json:"service" binding:"required"`   // ED Journal name of the service
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
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	// check if carrier exists using market id
	cr := entities.Carrier{}
	if res := db.DB.Where("market_id = ?", dto.MarketID).First(&cr); res.Error != nil {
		if !user.IsAdmin && (token == nil || !token.HasFullWriteAccess) {
			errors.ReturnWithError(c, carrier.ErrForbidden)
			return
		}
		errors.ReturnWithError(c, carrier.ErrCarrierNotFound)
		return
	}

	// check if user is admin or token has full write access
	if !user.IsAdmin && (token == nil || !token.HasWriteAccessToCarrier(cr.ID)) {
		if cr.OwnerID != nil && *cr.OwnerID != user.ID {
			errors.ReturnWithError(c, carrier.ErrForbidden)
			return
		}
	}

	// update carrier
	service, exists := entities.CarrierServices[dto.Service]
	if !exists {
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	switch dto.Operation {
	case "activate", "resume":
		cr.AddService(service)
	case "deactivate", "pause":
		cr.RemoveService(service)
	default:
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	if res := db.DB.Save(&cr); res.Error != nil {
		c.Error(res.Error)
		errors.ReturnWithError(c, carrier.ErrInternalServerError)
		return
	}

	c.JSON(200, gin.H{"success": true})
}
