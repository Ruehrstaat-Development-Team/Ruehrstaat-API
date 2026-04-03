package migrations

import "gorm.io/gorm"

const migrationFido2DisplayNameUserScopedUniqueID = "20260402_004_fido2_display_name_user_scoped_unique"

var migrationFido2DisplayNameUserScopedUnique = Migration{
	ID:       migrationFido2DisplayNameUserScopedUniqueID,
	Desc:     "Drop global FIDO2 display-name uniqueness so names are only unique per user",
	Requires: []string{"fido2_logins"},
	Up: func(db *gorm.DB) error {
		if db.Dialector.Name() != "postgres" {
			return nil
		}

		statements := []string{
			`ALTER TABLE fido2_logins DROP CONSTRAINT IF EXISTS uni_fido2_logins_display_name`,
			`ALTER TABLE fido2_logins DROP CONSTRAINT IF EXISTS fido2_logins_display_name_key`,
			`DROP INDEX IF EXISTS idx_fido2_logins_display_name`,
			`DROP INDEX IF EXISTS uni_fido2_logins_display_name`,
		}

		for _, statement := range statements {
			if err := db.Exec(statement).Error; err != nil {
				return err
			}
		}

		return nil
	},
}
