package auth

import (
	"context"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/util"
	"time"

	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
)

func RequestPassiveLoginToken(ctx context.Context, clientIP string) (string, string, *errors.RstError) {
	if err := checkPassiveLoginRequestRateLimit(ctx, clientIP); err != nil {
		return "", "", err
	}
	incrementPassiveLoginRequestAttempt(ctx, clientIP)

	// generate a v4 uuid, save it in redis with 5 minute expiration as key with "pending" state and return token
	var token string
	var err error

	token = uuid.New().String()

	if cache.HasState("passive_login_session", token) {
		return "", "", ErrPassiveLoginTokenRequestFailed
	}

	sessionID, err := util.GenerateRandomString(32)
	if err != nil {
		return "", "", errors.NewFromError(err)
	}

	// save token in redis with 5 minute expiration
	cache.BeginSpecificState("passive_login", token, "pending", time.Minute*5)
	cache.BeginSpecificState("passive_login_session", token, sessionID, time.Minute*10)

	return token, sessionID, nil
}

func VerifyPassiveLoginToken(ctx context.Context, token string, user *entities.User) *errors.RstError {
	if err := checkPassiveLoginRateLimit(ctx, user.ID.String()); err != nil {
		return err
	}

	var payload string

	// Keep the pending state until completion so the requester can finish the flow.
	if !cache.GetState("passive_login", token, &payload) {
		incrementPassiveLoginFailedAttempt(ctx, user.ID.String())
		return ErrInvalidToken
	}

	// if token is not pending, return
	if payload != "pending" {
		incrementPassiveLoginFailedAttempt(ctx, user.ID.String())
		return ErrInvalidToken
	}

	if !bindPassiveLoginVerification(ctx, token, user.ID.String()) {
		incrementPassiveLoginFailedAttempt(ctx, user.ID.String())
		return ErrInvalidToken
	}

	resetPassiveLoginFailedAttempts(ctx, user.ID.String())

	return nil
}

func bindPassiveLoginVerification(ctx context.Context, token string, userID string) bool {
	key := "state:passive_login_verified:" + token
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

func CompletePassiveLogin(token string, sessionID string) (*string, *errors.RstError) {
	if sessionID == "" {
		return nil, ErrInvalidToken
	}

	var sessionIDInRedis string
	if !cache.GetState("passive_login_session", token, &sessionIDInRedis) {
		return nil, ErrInvalidToken
	}

	if sessionID != sessionIDInRedis {
		return nil, ErrInvalidToken
	}

	if !cache.HasState("passive_login_verified", token) {
		if !cache.HasState("passive_login", token) {
			return nil, ErrInvalidToken
		}
		return nil, ErrPassiveLoginTokenNotYetVerified
	}

	var userID string

	// check if token is verified in redis, if so, set user_id as payload
	if !cache.EndState("passive_login_verified", token, &userID) {
		return nil, ErrInvalidToken
	}

	// if token is not verified, return
	if userID == "" {
		return nil, ErrInvalidToken
	}

	var pendingState string
	if !cache.EndState("passive_login", token, &pendingState) {
		return nil, ErrInvalidToken
	}

	if pendingState != "pending" {
		return nil, ErrInvalidToken
	}

	var consumedSessionID string
	if !cache.EndState("passive_login_session", token, &consumedSessionID) {
		return nil, ErrInvalidToken
	}

	if consumedSessionID != sessionID {
		return nil, ErrInvalidToken
	}

	// return user_id
	return &userID, nil
}
