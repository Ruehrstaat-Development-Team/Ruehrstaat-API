package auth

import (
	"context"
	"time"

	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/util"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	allowlistKeyPrefix      = "jti:"
	revokedSessionKeyPrefix = "revoked_session:"
)

func allowlistKeyFromJTI(jti string) string {
	return allowlistKeyPrefix + util.HashToken(jti)
}

func revokedSessionKey(sid uuid.UUID) string {
	return revokedSessionKeyPrefix + sid.String()
}

func cacheRevokedSession(ctx context.Context, sid uuid.UUID, expiresAt time.Time) {
	if cache.Redis == nil {
		return
	}

	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	_ = cache.Redis.Set(ctx, revokedSessionKey(sid), "1", ttl).Err()
}

func setAccessTokenAllowlist(ctx context.Context, jti string, sid uuid.UUID, expiresAt int64) error {
	if cache.Redis == nil {
		return nil
	}

	ttl := time.Until(time.Unix(expiresAt, 0))
	if ttl <= 0 {
		return nil
	}
	return cache.Redis.Set(ctx, allowlistKeyFromJTI(jti), sid.String(), ttl).Err()
}

func checkAccessTokenAllowlist(ctx context.Context, jti string, sid uuid.UUID, userID uuid.UUID) bool {
	key := allowlistKeyFromJTI(jti)

	jtiHash := util.HashToken(jti)
	rec := &entities.AccessTokenJTI{}
	res := db.DB.WithContext(ctx).Where("jti_hash = ? AND expires_at > ?", jtiHash, time.Now()).First(rec)
	if res.Error != nil {
		return false
	}
	if rec.SessionID != sid || rec.UserID != userID {
		return false
	}

	sess := &entities.RefreshToken{}
	if err := db.DB.WithContext(ctx).Where("id = ? AND user_id = ? AND is_revoked = ?", sid, userID, false).First(sess).Error; err != nil {
		return false
	}

	if cache.Redis != nil {
		restTTL := time.Until(rec.ExpiresAt)
		if restTTL > 0 {
			_ = cache.Redis.Set(ctx, key, sid.String(), restTTL).Err()
		}
	}

	return true
}

func deleteAllowlistForSession(ctx context.Context, sid uuid.UUID) {
	var jtIs []entities.AccessTokenJTI
	if err := db.DB.WithContext(ctx).Where("session_id = ?", sid).Find(&jtIs).Error; err == nil && cache.Redis != nil {
		for _, row := range jtIs {
			_ = cache.Redis.Del(ctx, allowlistKeyPrefix+row.JTIHash).Err()
		}
	}
	_ = db.DB.WithContext(ctx).Where("session_id = ?", sid).Delete(&entities.AccessTokenJTI{}).Error
}

func deleteAllowlistForUser(ctx context.Context, userID uuid.UUID) {
	var jtIs []entities.AccessTokenJTI
	if err := db.DB.WithContext(ctx).Where("user_id = ?", userID).Find(&jtIs).Error; err == nil && cache.Redis != nil {
		for _, row := range jtIs {
			_ = cache.Redis.Del(ctx, allowlistKeyPrefix+row.JTIHash).Err()
		}
	}
	_ = db.DB.WithContext(ctx).Where("user_id = ?", userID).Delete(&entities.AccessTokenJTI{}).Error
}

func RevokeSession(ctx context.Context, sid uuid.UUID) error {
	sess := &entities.RefreshToken{}
	if err := db.DB.WithContext(ctx).Where("id = ?", sid).First(sess).Error; err != nil {
		return err
	}
	if err := db.DB.WithContext(ctx).Model(&entities.RefreshToken{}).Where("id = ?", sid).Update("is_revoked", true).Error; err != nil {
		return err
	}
	cacheRevokedSession(ctx, sid, sess.ExpiresAt)
	deleteAllowlistForSession(ctx, sid)
	return nil
}

func RevokeAllSessionsForUserTx(ctx context.Context, tx *gorm.DB, userID uuid.UUID) error {
	if err := tx.WithContext(ctx).Model(&entities.RefreshToken{}).Where("user_id = ?", userID).Update("is_revoked", true).Error; err != nil {
		return err
	}

	return tx.WithContext(ctx).Where("user_id = ?", userID).Delete(&entities.AccessTokenJTI{}).Error
}

func RevokeAllSessionsForUser(ctx context.Context, userID uuid.UUID) error {
	var sessions []entities.RefreshToken
	_ = db.DB.WithContext(ctx).Where("user_id = ?", userID).Find(&sessions).Error
	if err := RevokeAllSessionsForUserTx(ctx, db.DB, userID); err != nil {
		return err
	}
	for _, sess := range sessions {
		cacheRevokedSession(ctx, sess.ID, sess.ExpiresAt)
	}
	deleteAllowlistForUser(ctx, userID)
	return nil
}
