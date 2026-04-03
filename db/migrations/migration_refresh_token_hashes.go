package migrations

import (
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/util"

	"gorm.io/gorm"
)

var migrationRefreshTokenHashBackfill = Migration{
	ID:       "20260402_001_refresh_token_hash_backfill",
	Desc:     "Backfill refresh token hashes for legacy plaintext session rows",
	Requires: []string{"refresh_tokens"},
	Up: func(db *gorm.DB) error {
		var sessions []entities.RefreshToken
		if err := db.Where("token <> '' AND (token_hash IS NULL OR token_hash = '')").Find(&sessions).Error; err != nil {
			return err
		}

		for _, session := range sessions {
			if err := db.Model(&entities.RefreshToken{}).Where("id = ?", session.ID).Update("token_hash", util.HashToken(session.Token)).Error; err != nil {
				return err
			}
		}

		return nil
	},
}
