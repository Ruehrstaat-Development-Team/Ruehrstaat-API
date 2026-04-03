package entities

import (
	"time"

	"github.com/google/uuid"
)

type AccessTokenJTI struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index"`
	SessionID uuid.UUID `gorm:"type:uuid;not null;index"`
	JTIHash   string    `gorm:"type:text;not null;uniqueIndex"`
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
}
