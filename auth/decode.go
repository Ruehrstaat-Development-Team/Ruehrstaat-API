package auth

import (
	"ruehrstaat-backend/errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type decodedToken struct {
	Subject   uuid.UUID
	ExpiresAt int64
}

func decodeToken(secret string, tokenString string) (*decodedToken, *errors.RstError) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSigningMethod
		}

		return []byte(secret), nil
	})

	if err != nil {
		return nil, errors.NewFromError(err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		subClaim, ok := claims["sub"]
		if !ok {
			return nil, ErrInvalidToken
		}

		expClaim, ok := claims["exp"]
		if !ok {
			return nil, ErrInvalidToken
		}

		subject, err := uuid.Parse(subClaim.(string))
		if err != nil {
			return nil, errors.NewFromError(err)
		}

		return &decodedToken{
			Subject:   subject,
			ExpiresAt: int64(expClaim.(float64)),
		}, nil
	} else {
		return nil, ErrInvalidToken
	}
}
