package migrations

import (
	goerrors "errors"
	"fmt"
	"log"
	"strings"
	"time"

	"ruehrstaat-backend/db/entities"

	"gorm.io/gorm"
)

const migrationAdvisoryLockID int64 = 2026040201

type Migration struct {
	ID       string
	Up       func(db *gorm.DB) error
	Desc     string
	Requires []string
}

var migrations = []Migration{
	migrationAuthSessionSchema,
	migrationRefreshTokenHashBackfill,
	migrationRefreshTokenPlaintextCleanup,
	migrationUserEmailCaseInsensitiveUnique,
	migrationUserEmailNormalizedTrimmedUnique,
	migrationFido2DisplayNameUserScopedUnique,
}

type runtimeSchemaRequirement struct {
	table   string
	columns []string
}

var runtimeSchemaRequirements = []runtimeSchemaRequirement{
	{
		table: "refresh_tokens",
		columns: []string{
			"created_at",
			"updated_at",
			"token_hash",
			"last_used_at",
			"expires_at",
			"auth_time",
			"client_ip",
			"user_agent",
			"device_name",
			"country",
			"region",
			"city",
			"session_type",
		},
	},
	{
		table: "access_token_jtis",
		columns: []string{
			"id",
			"user_id",
			"session_id",
			"jti_hash",
			"expires_at",
			"created_at",
		},
	},
}

type deferredMigrationError struct {
	reason string
}

func (e deferredMigrationError) Error() string {
	return e.reason
}

func RunMigrations(db *gorm.DB) {
	unlock, err := acquireMigrationLock(db)
	if err != nil {
		log.Panicf("Failed to acquire migration lock: %v", err)
	}
	defer unlock()

	if err := db.AutoMigrate(&entities.Migration{}); err != nil {
		log.Printf("Warning: Failed to create migrations table: %v", err)
		return
	}

	for _, m := range migrations {
		if missing := missingRequiredTables(m.Requires, func(table string) bool {
			return db.Migrator().HasTable(table)
		}); len(missing) > 0 {
			log.Printf("Migration %s deferred: missing required tables: %s", m.ID, strings.Join(missing, ", "))
			continue
		}

		applied, err := isMigrationApplied(db, m.ID)
		if err != nil {
			log.Panicf("Failed to check migration %s state: %v", m.ID, err)
		}
		if applied {
			continue
		}

		log.Printf("Running migration: %s - %s", m.ID, m.Desc)
		if err := m.Up(db); err != nil {
			if isAlreadyExistsError(err) {
				log.Printf("Migration %s already applied, marking complete", m.ID)
				if err := markMigrationApplied(db, m.ID); err != nil {
					log.Panicf("Failed to mark migration %s as applied: %v", m.ID, err)
				}
				continue
			}

			var deferredErr deferredMigrationError
			if goerrors.As(err, &deferredErr) {
				log.Printf("Migration %s deferred: %v", m.ID, err)
				continue
			}

			log.Panicf("Migration %s failed: %v", m.ID, err)
		}

		if err := markMigrationApplied(db, m.ID); err != nil {
			log.Panicf("Failed to mark migration %s as applied: %v", m.ID, err)
		}
		log.Printf("Completed migration: %s", m.ID)
	}
}

func acquireMigrationLock(db *gorm.DB) (func(), error) {
	if db.Dialector.Name() != "postgres" {
		return func() {}, nil
	}
	if err := db.Exec("SELECT pg_advisory_lock(?)", migrationAdvisoryLockID).Error; err != nil {
		return nil, err
	}
	return func() {
		if err := db.Exec("SELECT pg_advisory_unlock(?)", migrationAdvisoryLockID).Error; err != nil {
			log.Printf("Warning: failed to release migration advisory lock: %v", err)
		}
	}, nil
}

func isAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "already exists") ||
		strings.Contains(errStr, "duplicate") ||
		strings.Contains(errStr, "42710") ||
		strings.Contains(errStr, "42p07")
}

func missingRequiredTables(required []string, hasTable func(string) bool) []string {
	if len(required) == 0 {
		return nil
	}

	missing := make([]string, 0, len(required))
	for _, table := range required {
		if table == "" {
			continue
		}
		if !hasTable(table) {
			missing = append(missing, table)
		}
	}

	return missing
}

func isMigrationApplied(db *gorm.DB, id string) (bool, error) {
	var count int64
	if err := db.Model(&entities.Migration{}).Where("id = ?", id).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func markMigrationApplied(db *gorm.DB, id string) error {
	return db.Create(&entities.Migration{ID: id, AppliedAt: time.Now()}).Error
}

func ValidateRuntimeSchema(db *gorm.DB) error {
	missing := missingRuntimeSchemaObjects(func(table string) bool {
		return db.Migrator().HasTable(table)
	}, func(table string, column string) bool {
		return db.Migrator().HasColumn(table, column)
	})
	if len(missing) == 0 {
		return nil
	}

	return fmt.Errorf("database schema is missing required auth/session objects: %s; run the tracked migrations or bootstrap the base schema before starting with DB_AUTOMIGRATE=false", strings.Join(missing, ", "))
}

func missingRuntimeSchemaObjects(hasTable func(string) bool, hasColumn func(string, string) bool) []string {
	missing := make([]string, 0)
	for _, requirement := range runtimeSchemaRequirements {
		if !hasTable(requirement.table) {
			missing = append(missing, requirement.table)
			continue
		}
		for _, column := range requirement.columns {
			if !hasColumn(requirement.table, column) {
				missing = append(missing, requirement.table+"."+column)
			}
		}
	}

	return missing
}
