package entities

import (
	"time"

	"github.com/google/uuid"
)

// Third party applications that can access the API.
type InfraToken struct {
	ID     uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	Name   string    `gorm:"type:varchar(255);not null;unique;index"`
	Secret string    `gorm:"type:varchar(255);not null"`
}

// API tokens for users.
type ApiToken struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index"`
	IsRevoked bool      `gorm:"type:boolean;not null;default:false"`
	ExpiresAt time.Time `gorm:"type:timestamp with time zone;not null;default:now() + interval '1 year'"`
	Prefix    string    `gorm:"type:varchar(255);not null;default:'';index"`
	Token     string    `gorm:"type:varchar(255);not null;default:''"`

	// Access rights
	HasFullReadAccess  bool `gorm:"type:boolean;not null;default:false"`
	HasFullWriteAccess bool `gorm:"type:boolean;not null;default:false"`

	// Carrier Access
	HasReadAccessTo  []uuid.UUID `gorm:"type:uuid[];not null;default:'{}'"`
	HasWriteAccessTo []uuid.UUID `gorm:"type:uuid[];not null;default:'{}'"`
}

func (t *ApiToken) HasReadAccessToCarrier(carrierId uuid.UUID) bool {
	if t.HasFullReadAccess {
		return true
	}
	for _, id := range t.HasReadAccessTo {
		if id == carrierId {
			return true
		}
	}
	return false
}

func (t *ApiToken) HasWriteAccessToCarrier(carrierId uuid.UUID) bool {
	if t.HasFullWriteAccess {
		return true
	}
	for _, id := range t.HasWriteAccessTo {
		if id == carrierId {
			return true
		}
	}
	return false
}
