package auth

import (
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/util"
	"time"
)

func RequestQuickLoginToken() (string, string, error) {
	// generate 6 digit random number, save it in redis with 5 minute expiration as key with "pending" state and return number
	var token string
	var err error
	count := 0
	for {
		token, err = util.GenerateRandomNumberString(6)
		if err != nil {
			return "", "", err
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
		return "", "", err
	}

	// save token in redis with 5 minute expiration
	cache.BeginSpecificState("quick_login", token, "pending", time.Minute*5)
	cache.BeginSpecificState("quick_login_session", token, sessionID, time.Minute*10)

	return token, sessionID, nil
}

func VerifyQuickLoginToken(token string, user *entities.User) error {
	var payload string

	// check if token is pending in redis, if so, set user as payload
	if !cache.EndState("quick_login", token, &payload) {
		return ErrInvalidToken
	}

	// if token is not pending, return
	if payload != "pending" {
		return ErrInvalidToken
	}

	// set user_id in redis with 5 minute expiration
	cache.BeginSpecificState("quick_login_verified", token, user.ID, time.Minute*5)

	return nil
}

func CompleteQuickLogin(token string, sessionID string) (string, error) {
	// check if token is verified in redis, if so, return user_id
	var userId string
	if !cache.EndState("quick_login_verified", token, &userId) {
		return "", ErrInvalidToken
	}

	// check if sessionID is correct
	var sessionIDInRedis string
	if !cache.EndState("quick_login_session", token, &sessionIDInRedis) {
		return "", ErrInvalidToken
	}

	if sessionID != sessionIDInRedis {
		return "", ErrInvalidToken
	}

	return userId, nil
}
