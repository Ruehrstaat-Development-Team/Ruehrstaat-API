package entities

import (
	"ruehrstaat-backend/errors"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// represents an Elite Dangerous Fleet Carrier
type Carrier struct {
	gorm.Model
	ID              uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	MarketID        string    `gorm:"type:varchar(255);not null;unique;index"`
	Name            string    `gorm:"type:varchar(255);not null;index"`
	Callsign        string    `gorm:"type:varchar(255);not null;unique;index"`
	CurrentLocation string    `gorm:"type:varchar(255);not null"`
	// location history of the carrier as list of strings
	LocationHistory pq.StringArray `gorm:"type:varchar(255)[];not null;default:'{}'"`

	// Carrier Services
	Services     []CarrierService `gorm:"-"`
	ServiceNames pq.StringArray   `gorm:"type:varchar(255)[];not null;default:'{}'"`

	DockingAccess  CarrierDockingAccess `gorm:"type:varchar(255);not null;default:'all'"` // all, none, friends, squadron, squadronfriends
	AllowNotorious bool                 `gorm:"type:boolean;not null;default:false"`

	// Fuel Level, number between 0 and 1000 inclusive
	FuelLevel int `gorm:"type:integer;not null;default:0"`

	// Cargo Space, number between 0 and 25000 inclusive
	CargoSpace int `gorm:"type:integer;not null;default:0"`
	CargoUsed  int `gorm:"type:integer;not null;default:0"`

	Balance          int64 `gorm:"type:bigint;not null;default:0"`
	ReserveBalance   int64 `gorm:"type:bigint;not null;default:0"`
	AvailableBalance int64 `gorm:"type:bigint;not null;default:0"`

	// Optional OwnerID (User)
	OwnerID *uuid.UUID `gorm:"type:uuid;index"`
	Owner   *User      `gorm:"foreignKey:OwnerID"`

	// Carrier Category
	Category CarrierCategory `gorm:"type:varchar(255);not null;default:'other'"` // other, flagship, freighter, supportvessel
}

func (c *Carrier) AfterFind(tx *gorm.DB) (err error) {
	c.Services = []CarrierService{}
	for _, serviceName := range c.ServiceNames {
		c.Services = append(c.Services, CarrierServices[serviceName])
	}
	return
}

func (c *Carrier) BeforeSave(tx *gorm.DB) (err error) {
	c.ServiceNames = []string{}
	for _, service := range c.Services {
		c.ServiceNames = append(c.ServiceNames, service.Name)
	}
	return
}

// set DockingAccess from string
func (c *Carrier) SetDockingAccess(access string) *errors.RstError {
	switch CarrierDockingAccess(access) {
	case DockingAccessAll, DockingAccessNone, DockingAccessFriends, DockingAccessSquadron, DockingAccessSquadronAndFriends:
		c.DockingAccess = CarrierDockingAccess(access)
		return nil
	default:
		return InvalidDockingAccessError
	}
}

// set Category from string
func (c *Carrier) SetCategory(category string) *errors.RstError {
	switch CarrierCategory(category) {
	case CarrierCategoryOther, CarrierCategoryFlagship, CarrierCategoryFreighter, CarrierCategorySupportVessel:
		c.Category = CarrierCategory(category)
		return nil
	default:
		return InvalidCategoryError
	}
}

func (c *Carrier) HasService(service CarrierService) bool {
	for _, s := range c.Services {
		if s.Name == service.Name {
			return true
		}
	}
	return false
}

// set servies from string array (have a bool to override existing services)
func (c *Carrier) SetServices(services []string, override bool) *errors.RstError {
	if override {
		c.Services = []CarrierService{}
	}
	// append services that are not already in the list
	for _, serviceName := range services {
		service, exists := CarrierServices[serviceName]
		if !exists {
			return InvalidServiceError
		}
		if !c.HasService(service) {
			c.Services = append(c.Services, service)
		}
	}
	return nil
}

// remove carrier service from services
func (c *Carrier) RemoveService(service CarrierService) {
	for i, s := range c.Services {
		if s.Name == service.Name {
			c.Services = append(c.Services[:i], c.Services[i+1:]...)
		}
	}
}

// add carrier service to services
func (c *Carrier) AddService(service CarrierService) {
	if !c.HasService(service) {
		c.Services = append(c.Services, service)
	}
}

type CarrierService struct {
	Name        string `gorm:"-"`
	Label       string `gorm:"-"`
	OdysseyOnly bool   `gorm:"-"`
}

var CarrierServices = map[string]CarrierService{
	"Bartender": {
		Name:        "Bartender",
		Label:       "Concourse Bar",
		OdysseyOnly: true,
	},
	"PioneerSupplies": {
		Name:        "PioneerSupplies",
		Label:       "Pioneer Supplies",
		OdysseyOnly: true,
	},
	"VistaGenomics": {
		Name:        "VistaGenomics",
		Label:       "Vista Genomics",
		OdysseyOnly: true,
	},
	"Outfitting": {
		Name:        "Outfitting",
		Label:       "Outfitting",
		OdysseyOnly: false,
	},
	"Shipyard": {
		Name:        "Shipyard",
		Label:       "Shipyard",
		OdysseyOnly: false,
	},
	"Exploration": {
		Name:        "Exploration",
		Label:       "Universal Cartographics",
		OdysseyOnly: false,
	},
	"VoucherRedemption": {
		Name:        "VoucherRedemption",
		Label:       "Redemption Office",
		OdysseyOnly: false,
	},
	"Commodities": {
		Name:        "Commodities",
		Label:       "Commodities Market",
		OdysseyOnly: false,
	},
	"Rearm": {
		Name:        "Rearm",
		Label:       "Rearm",
		OdysseyOnly: false,
	},
	"Refuel": {
		Name:        "Refuel",
		Label:       "Refuel",
		OdysseyOnly: false,
	},
	"Repair": {
		Name:        "Repair",
		Label:       "Repair",
		OdysseyOnly: false,
	},
	"BlackMarket": {
		Name:        "BlackMarket",
		Label:       "Secure Trading",
		OdysseyOnly: false,
	},
}

type CarrierDockingAccess string

const (
	DockingAccessAll                CarrierDockingAccess = "all"
	DockingAccessNone               CarrierDockingAccess = "none"
	DockingAccessFriends            CarrierDockingAccess = "friends"
	DockingAccessSquadron           CarrierDockingAccess = "squadron"
	DockingAccessSquadronAndFriends CarrierDockingAccess = "squadronfriends"
)

type CarrierCategory string

const (
	CarrierCategoryOther         CarrierCategory = "other"
	CarrierCategoryFlagship      CarrierCategory = "flagship"
	CarrierCategoryFreighter     CarrierCategory = "freighter"
	CarrierCategorySupportVessel CarrierCategory = "supportvessel"
)

// errors

var ErrPackageCarrierEntity = errors.NewPackage("CarrierEntity", "CE")

// codes
// 1xxx - invalid something
// 2xxx - not found
// 3xxx - already done / exists
// 4xxx - forbidden
// 5xxx - server error

// 9xxx - other
// 9999 - unknown error

var (
	InvalidDockingAccessError = errors.New(1001, *ErrPackageCarrierEntity, 400, "", "Invalid Docking Access provided")
	InvalidCategoryError      = errors.New(1002, *ErrPackageCarrierEntity, 400, "", "Invalid Category provided")
	InvalidServiceError       = errors.New(1003, *ErrPackageCarrierEntity, 400, "", "Invalid Service provided")
)
