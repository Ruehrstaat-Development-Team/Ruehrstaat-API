package serialize

import (
	"ruehrstaat-backend/db/entities"

	"github.com/gin-gonic/gin"
)

type CarrierSerializer struct {
	// Whether to include the full user object (true) or just specific fields
	Full bool `json:"full"`
}

func (s *CarrierSerializer) Serialize(carrier entities.Carrier) interface{} {
	obj := &JsonObj{
		"id":              carrier.ID,
		"name":            carrier.Name,
		"callsign":        carrier.Callsign,
		"currentLocation": carrier.CurrentLocation,
		"dockingAccess":   carrier.DockingAccess,
		"services":        DoArray[entities.CarrierService](&CarrierServiceSerializer{}, carrier.Services),
		"category":        carrier.Category,
	}
	if s.Full {
		obj.Add("fuelLevel", carrier.FuelLevel)
		obj.Add("cargoSpace", carrier.CargoSpace)
		obj.Add("cargoUsed", carrier.CargoUsed)
		obj.Add("balance", carrier.Balance)
		obj.Add("reserveBalance", carrier.ReserveBalance)
		obj.Add("availableBalance", carrier.AvailableBalance)
	}

	if carrier.Owner != nil {
		obj.Add("owner", carrier.Owner.CmdrName)
		obj.Add("ownerDiscordId", carrier.Owner.DiscordId)
	}

	return obj
}

func (s *CarrierSerializer) ParseFlags(c *gin.Context) *CarrierSerializer {
	s.Full = c.Query("full") == "true"
	return s
}

type CarrierServiceSerializer struct {
}

func (s *CarrierServiceSerializer) Serialize(service entities.CarrierService) interface{} {
	obj := &JsonObj{
		"name":    service.Name,
		"label":   service.Label,
		"odyssey": service.OdysseyOnly,
	}
	return obj
}

func (s *CarrierServiceSerializer) ParseFlags(c *gin.Context) *CarrierServiceSerializer {
	return s
}
