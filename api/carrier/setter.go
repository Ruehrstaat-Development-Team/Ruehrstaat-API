package carrier

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/serialize"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func createCarrier(c *gin.Context) {
	user := c.MustGet("user").(*entities.User)
	tokenValue, exists := c.Get("token")
	token := &entities.ApiToken{}
	if exists {
		token = tokenValue.(*entities.ApiToken)
	}

	// check if user is admin or token has full write access
	if !user.IsAdmin && (token == nil || !token.HasFullWriteAccess) {
		c.JSON(403, gin.H{"error": "Forbidden"})
		return
	}

	carrierDto := createCarrierDto{}
	if err := c.ShouldBindJSON(&carrierDto); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// check if carrier with same name or callsign already exists
	if res := db.DB.Where("name = ? OR callsign = ?", carrierDto.Name, carrierDto.Callsign).First(&entities.Carrier{}); res.Error == nil {
		c.JSON(409, gin.H{"error": "Carrier with same name or callsign already exists"})
		return
	}

	carrier := entities.Carrier{
		MarketID:        carrierDto.MarketID,
		Name:            carrierDto.Name,
		Callsign:        carrierDto.Callsign,
		CurrentLocation: carrierDto.CurrentLocation,
		AllowNotorious:  carrierDto.AllowNotorious,
		Services:        []entities.CarrierService{},
		FuelLevel:       carrierDto.FuelLevel,
		CargoSpace:      carrierDto.CargoSpace,
		CargoUsed:       carrierDto.CargoUsed,
		Balance:         carrierDto.Balance,
		ReserveBalance:  carrierDto.ReserveBalance,
	}

	// add Owner
	if carrierDto.OwnerID != nil {
		// if exists set owner and owner id
		user := entities.User{}
		if res := db.DB.Where("id = ?", carrierDto.OwnerID).First(&user); res.Error != nil {
			c.JSON(400, gin.H{"error": "Bad Request"})
			return
		}

		carrier.Owner = &user
		carrier.OwnerID = carrierDto.OwnerID
	}

	// add DockingAccess and Category
	if err := carrier.SetDockingAccess(carrierDto.DockingAccess); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	if err := carrier.SetCategory(carrierDto.Category); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// add Services
	if err := carrier.SetServices(carrierDto.Services, true); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	if res := db.DB.Create(&carrier); res.Error != nil {
		c.JSON(500, gin.H{"error": "Internal Server Error"})
		return
	}

	serialize.JSON[entities.Carrier](c, (&serialize.CarrierSerializer{}).ParseFlags(c), carrier)
}

func updateCarrierOverride(c *gin.Context) {
	user := c.MustGet("user").(*entities.User)
	tokenValue, exists := c.Get("token")
	token := &entities.ApiToken{}
	if exists {
		token = tokenValue.(*entities.ApiToken)
	}

	carrierIdStr := c.Param("id")
	if carrierIdStr == "" {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	carrierId, err := uuid.Parse(carrierIdStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	carrier := entities.Carrier{}
	if res := db.DB.Where("id = ?", carrierId).First(&carrier); res.Error != nil {
		if !user.IsAdmin || (token == nil || !token.HasFullWriteAccess) {
			c.JSON(403, gin.H{"error": "Forbidden"})
			return
		}
		c.JSON(404, gin.H{"error": "Carrier not found"})
		return
	}

	// check if user is admin, owner or token has write access
	if !user.IsAdmin && !(carrier.OwnerID != nil && user.ID == *carrier.OwnerID) && (token == nil || !token.HasWriteAccessToCarrier(carrierId)) {
		c.JSON(403, gin.H{"error": "Forbidden"})
		return
	}

	carrierDto := updateCarrierOverrideDto{}
	if err := c.ShouldBindJSON(&carrierDto); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// check if that market id or callsign is already in use and not by this carrier
	if res := db.DB.Where("id != ? AND (market_id = ? OR callsign = ?)", carrier.ID, carrierDto.MarketID, carrierDto.Callsign).First(&entities.Carrier{}); res.Error == nil {
		c.JSON(409, gin.H{"error": "Carrier with same market id or callsign already exists"})
		return
	}

	// update Carrier
	carrier.MarketID = carrierDto.MarketID
	carrier.Name = carrierDto.Name
	carrier.Callsign = carrierDto.Callsign
	carrier.CurrentLocation = carrierDto.CurrentLocation
	if carrierDto.LocationHistory != nil {
		carrier.LocationHistory = carrierDto.LocationHistory
	}
	carrier.AllowNotorious = carrierDto.AllowNotorious
	carrier.FuelLevel = carrierDto.FuelLevel
	carrier.CargoSpace = carrierDto.CargoSpace
	carrier.CargoUsed = carrierDto.CargoUsed
	carrier.Balance = carrierDto.Balance
	carrier.ReserveBalance = carrierDto.ReserveBalance

	// add Owner
	if carrierDto.OwnerID != nil {
		// if exists set owner and owner id
		user := entities.User{}
		if res := db.DB.Where("id = ?", carrierDto.OwnerID).First(&user); res.Error != nil {
			c.JSON(400, gin.H{"error": "Bad Request"})
			return
		}

		carrier.Owner = &user
		carrier.OwnerID = carrierDto.OwnerID
	} else {
		// if not exists remove owner and owner id
		carrier.Owner = nil
		carrier.OwnerID = nil
	}

	// add DockingAccess and Category
	if err := carrier.SetDockingAccess(carrierDto.DockingAccess); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	if err := carrier.SetCategory(carrierDto.Category); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	// add Services
	if err := carrier.SetServices(carrierDto.Services, false); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	if res := db.DB.Save(&carrier); res.Error != nil {
		c.JSON(500, gin.H{"error": "Internal Server Error"})
		return
	}

	serialize.JSON[entities.Carrier](c, (&serialize.CarrierSerializer{}).ParseFlags(c), carrier)
}

// PATCH /api/carrier/:id
func updateCarrier(c *gin.Context) {
	user := c.MustGet("user").(*entities.User)
	tokenValue, exists := c.Get("token")
	token := &entities.ApiToken{}
	if exists {
		token = tokenValue.(*entities.ApiToken)
	}

	carrierIdStr := c.Param("id")
	if carrierIdStr == "" {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	carrierId, err := uuid.Parse(carrierIdStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	carrier := entities.Carrier{}
	if res := db.DB.Where("id = ?", carrierId).First(&carrier); res.Error != nil {
		if !user.IsAdmin || (token == nil || !token.HasFullWriteAccess) {
			c.JSON(403, gin.H{"error": "Forbidden"})
			return
		}
		c.JSON(404, gin.H{"error": "Carrier not found"})
		return
	}

	// check if user is admin, owner or token has write access
	if !user.IsAdmin && !(carrier.OwnerID != nil && user.ID == *carrier.OwnerID) && (token == nil || !token.HasWriteAccessToCarrier(carrierId)) {
		c.JSON(403, gin.H{"error": "Forbidden"})
		return
	}

	carrierDto := updateCarrierDto{}
	if err := c.ShouldBindJSON(&carrierDto); err != nil {
		c.JSON(400, gin.H{"error": "Bad Request"})
		return
	}

	marketOrCallsignChanged := false

	// update Carrier
	if carrierDto.MarketID != nil {
		carrier.MarketID = *carrierDto.MarketID
		marketOrCallsignChanged = true
	}

	if carrierDto.Name != nil {
		carrier.Name = *carrierDto.Name
	}

	if carrierDto.Callsign != nil {
		carrier.Callsign = *carrierDto.Callsign
		marketOrCallsignChanged = true
	}

	if marketOrCallsignChanged {
		// check if carrier with same name or callsign already exists
		if res := db.DB.Where("id != ? AND (market_id = ? OR callsign = ?)", carrier.ID, carrierDto.MarketID, carrierDto.Callsign).First(&entities.Carrier{}); res.Error == nil {
			c.JSON(409, gin.H{"error": "Carrier with same name or callsign already exists"})
			return
		}
	}

	if carrierDto.CurrentLocation != nil {
		carrier.CurrentLocation = *carrierDto.CurrentLocation
	}

	if carrierDto.LocationHistory != nil {
		carrier.LocationHistory = *carrierDto.LocationHistory
	}

	if carrierDto.DockingAccess != nil {
		if err := carrier.SetDockingAccess(*carrierDto.DockingAccess); err != nil {
			c.JSON(400, gin.H{"error": "Bad Request"})
			return
		}
	}

	if carrierDto.AllowNotorious != nil {
		carrier.AllowNotorious = *carrierDto.AllowNotorious
	}

	if carrierDto.Services != nil {
		if err := carrier.SetServices(*carrierDto.Services, carrierDto.OverideServices); err != nil {
			c.JSON(400, gin.H{"error": "Bad Request"})
			return
		}
	}

	if carrierDto.FuelLevel != nil {
		carrier.FuelLevel = *carrierDto.FuelLevel
	}

	if carrierDto.CargoSpace != nil {
		carrier.CargoSpace = *carrierDto.CargoSpace
	}

	if carrierDto.CargoUsed != nil {
		carrier.CargoUsed = *carrierDto.CargoUsed
	}

	if carrierDto.Balance != nil {
		carrier.Balance = *carrierDto.Balance
	}

	if carrierDto.ReserveBalance != nil {
		carrier.ReserveBalance = *carrierDto.ReserveBalance
	}

	if carrierDto.OwnerID != nil && (user.IsAdmin || (token != nil || token.HasFullWriteAccess)) {
		// if exists set owner and owner id
		user := entities.User{}
		if res := db.DB.Where("id = ?", carrierDto.OwnerID).First(&user); res.Error != nil {
			c.JSON(400, gin.H{"error": "Bad Request"})
			return
		}

		carrier.Owner = &user
		carrier.OwnerID = carrierDto.OwnerID
	}

	if carrierDto.Category != nil {
		if err := carrier.SetCategory(*carrierDto.Category); err != nil {
			c.JSON(400, gin.H{"error": "Bad Request"})
			return
		}
	}

	if res := db.DB.Save(&carrier); res.Error != nil {
		c.JSON(500, gin.H{"error": "Internal Server Error"})
		return
	}

	serialize.JSON[entities.Carrier](c, (&serialize.CarrierSerializer{}).ParseFlags(c), carrier)
}
