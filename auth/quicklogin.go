package auth

import (
	"context"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/util"
	"time"

	jsoniter "github.com/json-iterator/go"
)

func RequestQuickLoginToken(ctx context.Context, clientIP string) (string, string, *errors.RstError) {
	if err := checkQuickLoginRequestRateLimit(ctx, clientIP); err != nil {
		return "", "", err
	}
	incrementQuickLoginRequestAttempt(ctx, clientIP)

	// generate 6 digit random number, save it in redis with 5 minute expiration as key with "pending" state and return number
	var token string
	var err error
	count := 0
	for {
		token, err = util.GenerateRandomNumberString(6)
		if err != nil {
			return "", "", errors.NewFromError(err)
		}

		if !cache.HasState("quick_login_session", token) {
			break
		}
		count += 1
		if count > 10 {
			return "", "", ErrServer
		}
	}

	sessionID, err := util.GenerateRandomString(32)
	if err != nil {
		return "", "", errors.NewFromError(err)
	}

	// save token in redis with 5 minute expiration
	cache.BeginSpecificState("quick_login", token, "pending", time.Minute*5)
	cache.BeginSpecificState("quick_login_session", token, sessionID, time.Minute*10)

	return token, sessionID, nil
}

func VerifyQuickLoginToken(ctx context.Context, token string, user *entities.User) *errors.RstError {
	if err := checkQuickLoginRateLimit(ctx, user.ID.String()); err != nil {
		return err
	}

	var payload string

	// check if token is pending in redis, if so, set user as payload
	if !cache.GetState("quick_login", token, &payload) {
		incrementQuickLoginFailedAttempt(ctx, user.ID.String())
		return ErrInvalidToken
	}

	// if token is not pending, return
	if payload != "pending" {
		incrementQuickLoginFailedAttempt(ctx, user.ID.String())
		return ErrInvalidToken
	}

	if !bindQuickLoginVerification(ctx, token, user.ID.String()) {
		incrementQuickLoginFailedAttempt(ctx, user.ID.String())
		return ErrInvalidToken
	}

	resetQuickLoginFailedAttempts(ctx, user.ID.String())

	return nil
}

func bindQuickLoginVerification(ctx context.Context, token string, userID string) bool {
	key := "state:quick_login_verified:" + token
	encodedUserID, err := jsoniter.Marshal(userID)
	if err != nil {
		panic(err)
	}

	bound, err := cache.Redis.SetNX(ctx, key, encodedUserID, time.Minute*5).Result()
	if err != nil {
		panic(err)
	}
	if bound {
		return true
	}

	rawExistingUserID, err := cache.Redis.Get(ctx, key).Result()
	if err != nil {
		return false
	}

	var existingUserID string
	if err := jsoniter.Unmarshal([]byte(rawExistingUserID), &existingUserID); err != nil {
		return false
	}

	return existingUserID == userID
}

func CompleteQuickLogin(token string, sessionID string) (string, *errors.RstError) {
	if sessionID == "" {
		return "", ErrInvalidToken
	}

	var sessionIDInRedis string
	if !cache.GetState("quick_login_session", token, &sessionIDInRedis) {
		return "", ErrInvalidToken
	}

	if sessionID != sessionIDInRedis {
		return "", ErrInvalidToken
	}

	if !cache.HasState("quick_login_verified", token) {
		if !cache.HasState("quick_login", token) {
			return "", ErrInvalidToken
		}
		return "", ErrInvalidToken
	}

	var userId string
	if !cache.EndState("quick_login_verified", token, &userId) {
		return "", ErrInvalidToken
	}
	if userId == "" {
		return "", ErrInvalidToken
	}

	var pendingState string
	if !cache.EndState("quick_login", token, &pendingState) {
		return "", ErrInvalidToken
	}
	if pendingState != "pending" {
		return "", ErrInvalidToken
	}

	var consumedSessionID string
	if !cache.EndState("quick_login_session", token, &consumedSessionID) {
		return "", ErrInvalidToken
	}
	if consumedSessionID != sessionID {
		return "", ErrInvalidToken
	}

	return userId, nil
}
