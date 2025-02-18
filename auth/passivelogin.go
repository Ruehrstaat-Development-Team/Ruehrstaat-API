package auth

import (
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/util"
	"time"

	"github.com/google/uuid"
)

func RequestPassiveLoginToken() (string, string, *errors.RstError) {
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

func VerifyPassiveLoginToken(token string, user *entities.User) *errors.RstError {
	var payload string

	// check if token is pending in redis, if so, set user as payload
	if !cache.EndState("passive_login", token, &payload) {
		return ErrInvalidToken
	}

	// if token is not pending, return
	if payload != "pending" {
		return ErrInvalidToken
	}

	// set user_id in redis with 5 minute expiration
	cache.BeginSpecificState("passive_login_verified", token, user.ID, time.Minute*5)

	return nil
}

func CompletePassiveLogin(token string, sessionID string) (*string, *errors.RstError) {
	if !cache.HasState("passive_login", token) {
		return nil, ErrInvalidToken
	}

	if !cache.HasState("passive_login_session", token) {
		return nil, ErrInvalidToken
	}

	if !cache.HasState("passive_login_verified", token) {
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

	// check if sessionID matches the one in redis
	if !cache.EndState("passive_login_session", token, &sessionID) {
		return nil, ErrInvalidToken
	}

	// if sessionID is invalid, return
	if sessionID == "" {
		return nil, ErrInvalidToken
	}

	// return user_id
	return &userID, nil
}
