package carrier

import (
	"github.com/google/uuid"
)

type createCarrierDto struct {
	MarketID        string `json:"marketId" binding:"required"`
	Name            string `json:"name" binding:"required"`
	Callsign        string `json:"callsign" binding:"required"`
	CurrentLocation string `json:"currentLocation" binding:"required"`

	DockingAccess  string `json:"dockingAccess" binding:"required"`
	AllowNotorious bool   `json:"allowNotorious"`

	Services []string `json:"services"`

	FuelLevel  int `json:"fuelLevel"`
	CargoSpace int `json:"cargoSpace"`
	CargoUsed  int `json:"cargoUsed"`

	Balance          int64 `json:"balance"`
	ReserveBalance   int64 `json:"reserveBalance"`
	AvailableBalance int64 `json:"availableBalance"`

	OwnerID *uuid.UUID `json:"ownerId"`

	Category string `json:"category"`
}

type updateCarrierOverrideDto struct {
	MarketID        string `json:"marketId"`
	Name            string `json:"name"`
	Callsign        string `json:"callsign"`
	CurrentLocation string `json:"currentLocation"`

	LocationHistory []string `json:"locationHistory"`

	DockingAccess  string `json:"dockingAccess"`
	AllowNotorious bool   `json:"allowNotorious"`

	Services []string `json:"services"`

	FuelLevel  int `json:"fuelLevel"`
	CargoSpace int `json:"cargoSpace"`
	CargoUsed  int `json:"cargoUsed"`

	Balance          int64 `json:"balance"`
	ReserveBalance   int64 `json:"reserveBalance"`
	AvailableBalance int64 `json:"availableBalance"`

	OwnerID *uuid.UUID `json:"ownerId"`

	Category string `json:"category"`
}

type updateCarrierDto struct {
	MarketID        *string `json:"marketId"`
	Name            *string `json:"name"`
	Callsign        *string `json:"callsign"`
	CurrentLocation *string `json:"currentLocation"`

	LocationHistory *[]string `json:"locationHistory"`

	DockingAccess  *string `json:"dockingAccess"`
	AllowNotorious *bool   `json:"allowNotorious"`

	Services        *[]string `json:"services"`
	OverideServices bool      `json:"overrideServices"`

	FuelLevel  *int `json:"fuelLevel"`
	CargoSpace *int `json:"cargoSpace"`
	CargoUsed  *int `json:"cargoUsed"`

	Balance          *int64 `json:"balance"`
	ReserveBalance   *int64 `json:"reserveBalance"`
	AvailableBalance *int64 `json:"availableBalance"`

	OwnerID *uuid.UUID `json:"ownerId"`

	Category *string `json:"category"`
}
