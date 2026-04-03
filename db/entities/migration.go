package entities

import "time"

type Migration struct {
	ID        string    `gorm:"primaryKey;type:varchar(255)"`
	AppliedAt time.Time `gorm:"not null"`
}

func (Migration) TableName() string {
	return "db_migrations"
}
