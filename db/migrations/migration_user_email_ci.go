package migrations

import (
	"log"

	"gorm.io/gorm"
)

const migrationUserEmailCaseInsensitiveUniqueID = "20260402_002_user_email_ci_unique"

var migrationUserEmailCaseInsensitiveUnique = Migration{
	ID:       migrationUserEmailCaseInsensitiveUniqueID,
	Desc:     "Enforce case-insensitive unique email index",
	Requires: []string{"users"},
	Up: func(db *gorm.DB) error {
		if db.Dialector.Name() != "postgres" {
			return nil
		}

		if err := db.Exec(`
			CREATE TABLE IF NOT EXISTS user_email_ci_conflicts (
				user_id uuid PRIMARY KEY,
				original_email text NOT NULL,
				normalized_email text NOT NULL,
				created_at timestamp NOT NULL DEFAULT NOW()
			)
		`).Error; err != nil {
			return err
		}

		if err := db.Exec(`DELETE FROM user_email_ci_conflicts`).Error; err != nil {
			return err
		}

		if err := db.Exec(`
			WITH ranked AS (
				SELECT id, email, LOWER(REGEXP_REPLACE(email, '^[[:space:]]+|[[:space:]]+$', '', 'g')) AS normalized_email, COUNT(*) OVER (PARTITION BY LOWER(REGEXP_REPLACE(email, '^[[:space:]]+|[[:space:]]+$', '', 'g'))) AS cnt
				FROM users
			)
			INSERT INTO user_email_ci_conflicts (user_id, original_email, normalized_email)
			SELECT id, email, normalized_email
			FROM ranked
			WHERE cnt > 1
			ON CONFLICT (user_id) DO UPDATE SET
				original_email = EXCLUDED.original_email,
				normalized_email = EXCLUDED.normalized_email
		`).Error; err != nil {
			return err
		}

		if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_users_email_lower_lookup ON users (LOWER(REGEXP_REPLACE(email, '^[[:space:]]+|[[:space:]]+$', '', 'g')))`).Error; err != nil {
			return err
		}

		type dupRow struct {
			Email string
			Count int64
		}

		var dup dupRow
		if err := db.Raw(`
			SELECT LOWER(REGEXP_REPLACE(email, '^[[:space:]]+|[[:space:]]+$', '', 'g')) AS email, COUNT(*) AS count
			FROM users
			GROUP BY LOWER(REGEXP_REPLACE(email, '^[[:space:]]+|[[:space:]]+$', '', 'g'))
			HAVING COUNT(*) > 1
			LIMIT 1
		`).Scan(&dup).Error; err != nil {
			return err
		}

		if dup.Count > 1 {
			log.Printf("migration %s deferred: found case-insensitive email conflicts", migrationUserEmailCaseInsensitiveUniqueID)
			return deferredMigrationError{reason: "case-insensitive email duplicates exist; resolve rows listed in user_email_ci_conflicts before enabling idx_users_email_lower_unique"}
		}

		return db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower_unique ON users (LOWER(REGEXP_REPLACE(email, '^[[:space:]]+|[[:space:]]+$', '', 'g')))`).Error
	},
}
