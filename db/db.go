package db

import (
	"context"
	goerrors "errors"
	"fmt"
	"os"
	"strings"
	"time"

	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/db/migrations"
	"ruehrstaat-backend/logging"

	"github.com/getsentry/sentry-go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

var log = logging.Logger{Package: "db"}

const startupTimeout = 5 * time.Second

func Initialize() error {
	dsn := "host=" + os.Getenv("DB_HOST") + " user=" + os.Getenv("DB_USER") + " password=" + os.Getenv("DB_PASS") + " dbname=" + os.Getenv("DB_NAME") + " port=" + os.Getenv("DB_PORT") + " sslmode=disable TimeZone=Europe/Berlin connect_timeout=5"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("open database connection: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("get sql database handle: %w", err)
	}
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(time.Hour)

	startupCtx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	if err := sqlDB.PingContext(startupCtx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}

	db.Use(&GormSentryPlugin{})

	DB = db
	log.Println("Database initialized")

	if res := db.WithContext(startupCtx).Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"); res.Error != nil {
		return fmt.Errorf("enable uuid extension: %w", res.Error)
	}

	useAutoMigrate := os.Getenv("DB_AUTOMIGRATE") == "true"
	runTrackedMigrations := useAutoMigrate || strings.EqualFold(strings.TrimSpace(os.Getenv("DB_RUN_TRACKED_MIGRATIONS")), "true")
	if !useAutoMigrate {
		log.Println("Skipping database migration")
	} else {
		log.Println("Running database migration")
		err = db.WithContext(startupCtx).AutoMigrate(
			&entities.InfraToken{},
			&entities.User{},
			&entities.RefreshToken{},
			&entities.Fido2Login{},
			&entities.ApiToken{},
			&entities.AccessTokenJTI{},
			&entities.Carrier{},
		)
		if err != nil {
			return fmt.Errorf("auto migrate database schema: %w", err)
		}
		log.Println("Database Migration complete")
	}

	if runTrackedMigrations {
		if err := runTrackedMigrationsWithTimeout(startupCtx, DB); err != nil {
			return err
		}
	} else {
		log.Println("Skipping tracked migrations (enable DB_AUTOMIGRATE=true or DB_RUN_TRACKED_MIGRATIONS=true to run them)")
	}

	if err := validateRuntimeSchemaWithTimeout(startupCtx, DB); err != nil {
		return err
	}

	return nil
}

func runTrackedMigrationsWithTimeout(ctx context.Context, db *gorm.DB) error {
	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				errCh <- fmt.Errorf("tracked migrations panicked: %v", rec)
			}
		}()

		migrations.RunMigrations(db)
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("run tracked migrations: %w", ctx.Err())
	case err := <-errCh:
		if err != nil {
			return err
		}
		return nil
	}
}

func validateRuntimeSchemaWithTimeout(ctx context.Context, db *gorm.DB) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- migrations.ValidateRuntimeSchema(db)
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("validate runtime schema: %w", ctx.Err())
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("validate runtime schema: %w", err)
		}
		return nil
	}
}

type GormSentryPlugin struct{}

func (p *GormSentryPlugin) Name() string {
	return "gorm-sentry"
}

func (p *GormSentryPlugin) Initialize(db *gorm.DB) (err error) {
	db.Callback().Query().Before("gorm:query").Register("sentry:before_query", func(db *gorm.DB) {
		p.beforeQuery(db, "query")
	})
	db.Callback().Create().Before("gorm:create").Register("sentry:before_create", func(db *gorm.DB) {
		p.beforeQuery(db, "create")
	})
	db.Callback().Update().Before("gorm:update").Register("sentry:before_update", func(db *gorm.DB) {
		p.beforeQuery(db, "update")
	})
	db.Callback().Delete().Before("gorm:delete").Register("sentry:before_delete", func(db *gorm.DB) {
		p.beforeQuery(db, "delete")
	})
	db.Callback().Row().Before("gorm:row").Register("sentry:before_row", func(db *gorm.DB) {
		p.beforeQuery(db, "row")
	})
	db.Callback().Raw().Before("gorm:raw").Register("sentry:before_raw", func(db *gorm.DB) {
		p.beforeQuery(db, "raw")
	})

	db.Callback().Query().After("gorm:query").Register("sentry:after_query", func(db *gorm.DB) {
		p.afterQuery(db)
	})
	db.Callback().Create().After("gorm:create").Register("sentry:after_create", func(db *gorm.DB) {
		p.afterQuery(db)
	})
	db.Callback().Update().After("gorm:update").Register("sentry:after_update", func(db *gorm.DB) {
		p.afterQuery(db)
	})
	db.Callback().Delete().After("gorm:delete").Register("sentry:after_delete", func(db *gorm.DB) {
		p.afterQuery(db)
	})
	db.Callback().Row().After("gorm:row").Register("sentry:after_row", func(db *gorm.DB) {
		p.afterQuery(db)
	})
	db.Callback().Raw().After("gorm:raw").Register("sentry:after_raw", func(db *gorm.DB) {
		p.afterQuery(db)
	})

	return nil
}

func (p *GormSentryPlugin) beforeQuery(db *gorm.DB, query string) {
	if db.Statement.Context == context.Background() {
		return
	}

	transaction := sentry.TransactionFromContext(db.Statement.Context)
	if transaction == nil {
		return
	}

	span := sentry.StartSpan(db.Statement.Context, "db.query")
	span.Name = fmt.Sprintf("db.%s %s", query, db.Statement.Table)
	span.SetData("db.table", db.Statement.Table)
	span.SetData("db.query", query)
	db.InstanceSet("sentry:span", span)
}

func (p *GormSentryPlugin) afterQuery(db *gorm.DB) {
	span, ok := db.InstanceGet("sentry:span")
	if !ok {
		return
	}
	sp := span.(*sentry.Span)
	sp.Description = db.Statement.SQL.String()
	sp.Status = sentry.SpanStatusOK
	if db.Error != nil && !goerrors.Is(db.Error, gorm.ErrRecordNotFound) {
		sp.Status = sentry.SpanStatusInternalError
		sp.SetData("db.error", db.Error.Error())
	}
	sp.Finish()
}
