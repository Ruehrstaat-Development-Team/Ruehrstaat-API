package user_service

import (
	"context"
	"errors"
	"ruehrstaat-backend/db/entities"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func GetUserForUpdate(ctx context.Context, tx *gorm.DB, userID interface{}) (*entities.User, error) {
	user := &entities.User{}
	if err := tx.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", userID).First(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func WithLockedUser(ctx context.Context, dbConn *gorm.DB, userID interface{}, fn func(tx *gorm.DB, user *entities.User) error) error {
	if dbConn == nil {
		return errors.New("db is nil")
	}

	return dbConn.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockedUser, err := GetUserForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}

		return fn(tx, lockedUser)
	})
}

func SaveUserColumns(ctx context.Context, tx *gorm.DB, user *entities.User, columns ...string) error {
	if user == nil {
		return errors.New("user is nil")
	}
	if len(columns) == 0 {
		return errors.New("no columns provided")
	}

	return tx.WithContext(ctx).Model(user).Select(columns).Updates(user).Error
}
