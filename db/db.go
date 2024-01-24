package db

import (
	"os"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/logging"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

var log = logging.Logger{Package: "db"}

func Initialize() {
	dsn := "host=" + os.Getenv("DB_HOST") + " user=" + os.Getenv("DB_USER") + " password=" + os.Getenv("DB_PASS") + " dbname=" + os.Getenv("DB_NAME") + " port=" + os.Getenv("DB_PORT") + " sslmode=disable TimeZone=Europe/Berlin"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	DB = db
	log.Println("Database initialized")

	if res := db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"); res.Error != nil {
		panic(res.Error)
	}

	err = db.AutoMigrate(
		&entities.InfraToken{},
		&entities.User{},
		&entities.RefreshToken{},
		&entities.Fido2Login{},
		&entities.ApiToken{},

		&entities.Carrier{},
	)
	if err != nil {
		panic(err)
	}

	log.Println("Database Migration complete")

}
