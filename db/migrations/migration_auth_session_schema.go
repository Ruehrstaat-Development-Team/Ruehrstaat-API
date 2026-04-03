package migrations

import (
	"ruehrstaat-backend/db/entities"

	"gorm.io/gorm"
)

const migrationAuthSessionSchemaID = "20260403_001_auth_session_schema"

var migrationAuthSessionSchema = Migration{
	ID:       migrationAuthSessionSchemaID,
	Desc:     "Add required auth session columns and allowlist table",
	Requires: []string{"refresh_tokens"},
	Up: func(db *gorm.DB) error {
		refreshTokenColumns := []string{
			"CreatedAt",
			"UpdatedAt",
			"TokenHash",
			"LastUsedAt",
			"ExpiresAt",
			"AuthTime",
			"ClientIP",
			"UserAgent",
			"DeviceName",
			"Country",
			"Region",
			"City",
			"SessionType",
		}
		for _, column := range refreshTokenColumns {
			if !db.Migrator().HasColumn(&entities.RefreshToken{}, column) {
				if err := db.Migrator().AddColumn(&entities.RefreshToken{}, column); err != nil {
					return err
				}
			}
		}

		if !db.Migrator().HasTable(&entities.AccessTokenJTI{}) {
			if err := db.Migrator().CreateTable(&entities.AccessTokenJTI{}); err != nil {
				return err
			}
		}

		accessTokenColumns := []string{"ID", "UserID", "SessionID", "JTIHash", "ExpiresAt", "CreatedAt"}
		for _, column := range accessTokenColumns {
			if !db.Migrator().HasColumn(&entities.AccessTokenJTI{}, column) {
				if err := db.Migrator().AddColumn(&entities.AccessTokenJTI{}, column); err != nil {
					return err
				}
			}
		}

		return nil
	},
}
