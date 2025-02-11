package carrier

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/serialize"
	"ruehrstaat-backend/services/carrier"

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
		errors.ReturnWithError(c, carrier.ErrForbidden)
		return
	}

	carrierDto := createCarrierDto{}
	if err := c.ShouldBindJSON(&carrierDto); err != nil {
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	// check if carrier with same name or callsign already exists
	if res := db.DB.Where("name = ? OR callsign = ?", carrierDto.Name, carrierDto.Callsign).First(&entities.Carrier{}); res.Error == nil {
		errors.ReturnWithError(c, carrier.ErrCarrierAlreadyExists)
		return
	}

	cr := entities.Carrier{
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
			errors.ReturnWithError(c, carrier.ErrInvalidUserId)
			return
		}

		cr.Owner = &user
		cr.OwnerID = carrierDto.OwnerID
	}

	// add DockingAccess and Category
	if err := cr.SetDockingAccess(carrierDto.DockingAccess); err != nil {
		errors.ReturnWithError(c, carrier.ErrInvalidDockingAccess)
		return
	}

	if err := cr.SetCategory(carrierDto.Category); err != nil {
		errors.ReturnWithError(c, carrier.ErrInvalidCategory)
		return
	}

	// add Services
	if err := cr.SetServices(carrierDto.Services, true); err != nil {
		errors.ReturnWithError(c, carrier.ErrInvalidCarrierServices)
		return
	}

	if res := db.DB.Create(&cr); res.Error != nil {
		errors.ReturnWithError(c, carrier.ErrInternalServerError)
		return
	}

	serialize.JSON[entities.Carrier](c, (&serialize.CarrierSerializer{}).ParseFlags(c), cr)
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
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	carrierId, err := uuid.Parse(carrierIdStr)
	if err != nil {
		errors.ReturnWithError(c, carrier.ErrInvalidCarrierId)
		return
	}

	cr := entities.Carrier{}
	if res := db.DB.Where("id = ?", carrierId).First(&cr); res.Error != nil {
		if !user.IsAdmin || (token == nil || !token.HasFullWriteAccess) {
			errors.ReturnWithError(c, carrier.ErrForbidden)
			return
		}
		errors.ReturnWithError(c, carrier.ErrCarrierNotFound)
		return
	}

	// check if user is admin, owner or token has write access
	if !user.IsAdmin && !(cr.OwnerID != nil && user.ID == *cr.OwnerID) && (token == nil || !token.HasWriteAccessToCarrier(carrierId)) {
		errors.ReturnWithError(c, carrier.ErrForbidden)
		return
	}

	carrierDto := updateCarrierOverrideDto{}
	if err := c.ShouldBindJSON(&carrierDto); err != nil {
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	// check if that market id or callsign is already in use and not by this carrier
	if res := db.DB.Where("id != ? AND (market_id = ? OR callsign = ?)", cr.ID, carrierDto.MarketID, carrierDto.Callsign).First(&entities.Carrier{}); res.Error == nil {
		errors.ReturnWithError(c, carrier.ErrCarrierAlreadyExists)
		return
	}

	// update Carrier
	cr.MarketID = carrierDto.MarketID
	cr.Name = carrierDto.Name
	cr.Callsign = carrierDto.Callsign
	cr.CurrentLocation = carrierDto.CurrentLocation
	if carrierDto.LocationHistory != nil {
		cr.LocationHistory = carrierDto.LocationHistory
	}
	cr.AllowNotorious = carrierDto.AllowNotorious
	cr.FuelLevel = carrierDto.FuelLevel
	cr.CargoSpace = carrierDto.CargoSpace
	cr.CargoUsed = carrierDto.CargoUsed
	cr.Balance = carrierDto.Balance
	cr.ReserveBalance = carrierDto.ReserveBalance

	// add Owner
	if carrierDto.OwnerID != nil {
		// if exists set owner and owner id
		user := entities.User{}
		if res := db.DB.Where("id = ?", carrierDto.OwnerID).First(&user); res.Error != nil {
			errors.ReturnWithError(c, carrier.ErrInvalidUserId)
			return
		}

		cr.Owner = &user
		cr.OwnerID = carrierDto.OwnerID
	} else {
		// if not exists remove owner and owner id
		cr.Owner = nil
		cr.OwnerID = nil
	}

	// add DockingAccess and Category
	if err := cr.SetDockingAccess(carrierDto.DockingAccess); err != nil {
		errors.ReturnWithError(c, carrier.ErrInvalidDockingAccess)
		return
	}

	if err := cr.SetCategory(carrierDto.Category); err != nil {
		errors.ReturnWithError(c, carrier.ErrInvalidCategory)
		return
	}

	// add Services
	if err := cr.SetServices(carrierDto.Services, false); err != nil {
		errors.ReturnWithError(c, carrier.ErrInvalidCarrierServices)
		return
	}

	if res := db.DB.Save(&cr); res.Error != nil {
		errors.ReturnWithError(c, carrier.ErrInternalServerError)
		return
	}

	serialize.JSON[entities.Carrier](c, (&serialize.CarrierSerializer{}).ParseFlags(c), cr)
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
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	carrierId, err := uuid.Parse(carrierIdStr)
	if err != nil {
		errors.ReturnWithError(c, carrier.ErrInvalidCarrierId)
		return
	}

	cr := entities.Carrier{}
	if res := db.DB.Where("id = ?", carrierId).First(&cr); res.Error != nil {
		if !user.IsAdmin || (token == nil || !token.HasFullWriteAccess) {
			errors.ReturnWithError(c, carrier.ErrForbidden)
			return
		}
		errors.ReturnWithError(c, carrier.ErrCarrierNotFound)
		return
	}

	// check if user is admin, owner or token has write access
	if !user.IsAdmin && !(cr.OwnerID != nil && user.ID == *cr.OwnerID) && (token == nil || !token.HasWriteAccessToCarrier(carrierId)) {
		errors.ReturnWithError(c, carrier.ErrForbidden)
		return
	}

	carrierDto := updateCarrierDto{}
	if err := c.ShouldBindJSON(&carrierDto); err != nil {
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	marketOrCallsignChanged := false

	// update Carrier
	if carrierDto.MarketID != nil {
		cr.MarketID = *carrierDto.MarketID
		marketOrCallsignChanged = true
	}

	if carrierDto.Name != nil {
		cr.Name = *carrierDto.Name
	}

	if carrierDto.Callsign != nil {
		cr.Callsign = *carrierDto.Callsign
		marketOrCallsignChanged = true
	}

	if marketOrCallsignChanged {
		// check if carrier with same name or callsign already exists
		if res := db.DB.Where("id != ? AND (market_id = ? OR callsign = ?)", cr.ID, carrierDto.MarketID, carrierDto.Callsign).First(&entities.Carrier{}); res.Error == nil {
			errors.ReturnWithError(c, carrier.ErrCarrierAlreadyExists)
			return
		}
	}

	if carrierDto.CurrentLocation != nil {
		cr.CurrentLocation = *carrierDto.CurrentLocation
	}

	if carrierDto.LocationHistory != nil {
		cr.LocationHistory = *carrierDto.LocationHistory
	}

	if carrierDto.DockingAccess != nil {
		if err := cr.SetDockingAccess(*carrierDto.DockingAccess); err != nil {
			errors.ReturnWithError(c, carrier.ErrInvalidDockingAccess)
			return
		}
	}

	if carrierDto.AllowNotorious != nil {
		cr.AllowNotorious = *carrierDto.AllowNotorious
	}

	if carrierDto.Services != nil {
		if err := cr.SetServices(*carrierDto.Services, carrierDto.OverideServices); err != nil {
			errors.ReturnWithError(c, carrier.ErrInvalidCarrierServices)
			return
		}
	}

	if carrierDto.FuelLevel != nil {
		cr.FuelLevel = *carrierDto.FuelLevel
	}

	if carrierDto.CargoSpace != nil {
		cr.CargoSpace = *carrierDto.CargoSpace
	}

	if carrierDto.CargoUsed != nil {
		cr.CargoUsed = *carrierDto.CargoUsed
	}

	if carrierDto.Balance != nil {
		cr.Balance = *carrierDto.Balance
	}

	if carrierDto.ReserveBalance != nil {
		cr.ReserveBalance = *carrierDto.ReserveBalance
	}

	if carrierDto.OwnerID != nil && (user.IsAdmin || (token != nil || token.HasFullWriteAccess)) {
		// if exists set owner and owner id
		user := entities.User{}
		if res := db.DB.Where("id = ?", carrierDto.OwnerID).First(&user); res.Error != nil {
			errors.ReturnWithError(c, carrier.ErrInvalidUserId)
			return
		}

		cr.Owner = &user
		cr.OwnerID = carrierDto.OwnerID
	}

	if carrierDto.Category != nil {
		if err := cr.SetCategory(*carrierDto.Category); err != nil {
			errors.ReturnWithError(c, carrier.ErrInvalidCategory)
			return
		}
	}

	if res := db.DB.Save(&cr); res.Error != nil {
		errors.ReturnWithError(c, carrier.ErrInternalServerError)
		return
	}

	serialize.JSON[entities.Carrier](c, (&serialize.CarrierSerializer{}).ParseFlags(c), cr)
}
