package entities

import (
	"github.com/google/uuid"
)

// Third party applications that can access the API.
type InfraToken struct {
	ID     uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	Name   string    `gorm:"type:varchar(255);not null;unique;index"`
	Secret string    `gorm:"type:varchar(255);not null"`
}
