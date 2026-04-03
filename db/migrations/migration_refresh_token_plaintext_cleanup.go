package migrations

import (
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/util"

	"gorm.io/gorm"
)

const migrationRefreshTokenPlaintextCleanupID = "20260402_002_refresh_token_plaintext_cleanup"

var migrationRefreshTokenPlaintextCleanup = Migration{
	ID:       migrationRefreshTokenPlaintextCleanupID,
	Desc:     "Backfill hashes and remove legacy plaintext refresh tokens",
	Requires: []string{"refresh_tokens"},
	Up: func(db *gorm.DB) error {
		var sessions []entities.RefreshToken
		if err := db.Where("token <> ''").Find(&sessions).Error; err != nil {
			return err
		}

		for _, session := range sessions {
			updates := map[string]any{"token": ""}
			if session.TokenHash == "" {
				updates["token_hash"] = util.HashToken(session.Token)
			}
			if err := db.Model(&entities.RefreshToken{}).Where("id = ?", session.ID).Updates(updates).Error; err != nil {
				return err
			}
		}

		return nil
	},
}
