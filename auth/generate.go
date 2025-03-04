package auth

import (
	"log"
	"os"
	"ruehrstaat-backend/errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func generatePair(userID uuid.UUID, absoluteExpiration *int64) (TokenPair, *errors.RstError) {
	rexp := int64(0)
	if absoluteExpiration != nil {
		rexp = *absoluteExpiration
	} else {
		rexp = time.Now().Add(time.Hour * 24 * 30).Unix()
	}

	if rexp < time.Now().Unix() {
		return TokenPair{}, ErrAbsoluteExpReached
	}

	exp := time.Now().Add(time.Hour * 6).Unix()
	identityToken, err := generateToken(getIdentityTokenSecret(), userID.String(), exp)
	if err != nil {
		return TokenPair{}, err
	}

	refreshToken, err := generateToken(getRefreshTokenSecret(), userID.String(), rexp)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		RefreshToken: refreshToken,
		IdenityToken: identityToken,
		ExpiresAt:    exp,
	}, nil
}

func generateToken(secret string, sub string, exp int64) (string, *errors.RstError) {
	currTime := time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "Ruehrstaat Auth",
		"aud": "ruehrstaat.org",
		"sub": sub,
		"exp": exp,
		"iat": currTime,
		"nbf": currTime,
		"jti": uuid.New().String(),
	})

	val, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", errors.NewFromError(err)
	}
	return val, nil
}

func generateCustomToken(subject string, aud string, hoursExp int) (string, *errors.RstError) {
	currTime := time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "Ruehrstaat Auth",
		"aud": aud,
		"sub": subject,
		"exp": time.Now().Add(time.Hour * time.Duration(hoursExp)).Unix(),
		"iat": currTime,
		"nbf": currTime,
		"jti": uuid.New().String(),
	})

	val, err := token.SignedString([]byte(getIdentityTokenSecret()))
	if err != nil {
		return "", errors.NewFromError(err)
	}
	return val, nil
}

func getIdentityTokenSecret() string {
	secret, ok := os.LookupEnv("JWT_IDENTITY_SECRET")
	if !ok {
		log.Println("WARNING!!! JWT_IDENTITY_SECRET not set, using default value")
	}

	return secret
}

func getRefreshTokenSecret() string {
	secret, ok := os.LookupEnv("JWT_REFRESH_SECRET")
	if !ok {
		log.Println("WARNING!!! JWT_REFRESH_SECRET not set, using default value")
		return "secret"
	}

	return secret
}
