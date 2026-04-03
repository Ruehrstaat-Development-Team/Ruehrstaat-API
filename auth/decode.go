package auth

import (
	stdErrors "errors"
	"ruehrstaat-backend/errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type decodedToken struct {
	Subject   uuid.UUID
	ExpiresAt int64
	JTI       string
	SID       uuid.UUID
}

func decodeToken(secret string, tokenString string, expectedAudience string) (*decodedToken, *errors.RstError) {
	return decodeTokenInternal(secret, tokenString, expectedAudience, false)
}

func decodeTokenIgnoreExpiration(secret string, tokenString string, expectedAudience string) (*decodedToken, *errors.RstError) {
	return decodeTokenInternal(secret, tokenString, expectedAudience, true)
}

func decodeTokenInternal(secret string, tokenString string, expectedAudience string, ignoreExpiration bool) (*decodedToken, *errors.RstError) {
	parserOpts := []jwt.ParserOption{}
	if ignoreExpiration {
		parserOpts = append(parserOpts, jwt.WithoutClaimsValidation())
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, stdErrors.New(ErrInvalidSigningMethod.String())
		}

		return []byte(secret), nil
	}, parserOpts...)

	if err != nil {
		if stdErrors.Is(err, jwt.ErrTokenInvalidAudience) {
			return nil, ErrInvalidAudience
		}
		if stdErrors.Is(err, jwt.ErrTokenInvalidClaims) || stdErrors.Is(err, jwt.ErrInvalidType) || stdErrors.Is(err, jwt.ErrTokenInvalidSubject) || stdErrors.Is(err, jwt.ErrTokenInvalidId) {
			return nil, ErrInvalidToken
		}
		return nil, errors.NewFromError(err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && (token.Valid || ignoreExpiration) {
		if expectedAudience != "" {
			aud, err := claims.GetAudience()
			if err != nil || !audienceContains(aud, expectedAudience) {
				return nil, ErrInvalidAudience
			}
		}

		subjectClaim, err := claims.GetSubject()
		if err != nil || strings.TrimSpace(subjectClaim) == "" {
			return nil, ErrInvalidToken
		}

		expirationClaim, err := claims.GetExpirationTime()
		if err != nil || expirationClaim == nil {
			return nil, ErrInvalidToken
		}

		subject, err := uuid.Parse(subjectClaim)
		if err != nil {
			return nil, ErrInvalidToken
		}

		var sid uuid.UUID
		if sidVal, hasSid := claims["sid"]; hasSid {
			sidStr, ok := sidVal.(string)
			if !ok {
				return nil, ErrInvalidToken
			}
			if sidStr != "" {
				parsed, parseErr := uuid.Parse(sidStr)
				if parseErr != nil {
					return nil, ErrInvalidToken
				}
				sid = parsed
			}
		}

		jti := ""
		if jtiVal, hasJti := claims["jti"]; hasJti {
			s, ok := jtiVal.(string)
			if !ok {
				return nil, ErrInvalidToken
			}
			jti = s
		}

		return &decodedToken{
			Subject:   subject,
			ExpiresAt: expirationClaim.Unix(),
			JTI:       jti,
			SID:       sid,
		}, nil
	} else {
		return nil, ErrInvalidToken
	}
}

func audienceContains(audiences []string, expected string) bool {
	for _, audience := range audiences {
		if audience == expected {
			return true
		}
	}

	return false
}
