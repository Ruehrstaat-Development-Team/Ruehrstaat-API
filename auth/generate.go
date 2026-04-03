package auth

import (
	"log"
	"os"
	"time"

	"ruehrstaat-backend/errors"

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

	exp := time.Now().Add(time.Hour).Unix()
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

func generateIdentityTokenWithSession(secret string, sub string, sid uuid.UUID, exp int64) (tokenString string, jti string, err *errors.RstError) {
	currTime := time.Now().Unix()
	jti = uuid.New().String()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "Ruehrstaat Auth",
		"aud": "ruehrstaat.org",
		"sub": sub,
		"sid": sid.String(),
		"exp": exp,
		"iat": currTime,
		"nbf": currTime,
		"jti": jti,
	})

	val, signErr := token.SignedString([]byte(secret))
	if signErr != nil {
		return "", "", errors.NewFromError(signErr)
	}

	return val, jti, nil
}

func generateRefreshTokenWithSession(secret string, sub string, sid uuid.UUID, exp int64) (tokenString string, err *errors.RstError) {
	currTime := time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "Ruehrstaat Auth",
		"aud": "ruehrstaat.org",
		"sub": sub,
		"sid": sid.String(),
		"exp": exp,
		"iat": currTime,
		"nbf": currTime,
		"jti": uuid.New().String(),
	})

	val, signErr := token.SignedString([]byte(secret))
	if signErr != nil {
		return "", errors.NewFromError(signErr)
	}

	return val, nil
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
		log.Println("FATAL: JWT_IDENTITY_SECRET environment variable is not set")
		panic("JWT_IDENTITY_SECRET is required for secure token generation")
	}

	if len(secret) < 32 {
		log.Println("FATAL: JWT_IDENTITY_SECRET is too short (minimum 32 characters)")
		panic("JWT_IDENTITY_SECRET must be at least 32 characters long")
	}

	return secret
}

func getRefreshTokenSecret() string {
	secret, ok := os.LookupEnv("JWT_REFRESH_SECRET")
	if !ok {
		log.Println("FATAL: JWT_REFRESH_SECRET environment variable is not set")
		panic("JWT_REFRESH_SECRET is required for secure token generation")
	}

	if len(secret) < 16 {
		log.Println("FATAL: JWT_REFRESH_SECRET is too short (minimum 16 characters)")
		panic("JWT_REFRESH_SECRET must be at least 16 characters long")
	}

	return secret
}
